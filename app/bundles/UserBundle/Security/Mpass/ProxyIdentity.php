<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Symfony\Component\HttpFoundation\Request;

/**
 * Reads the identity oauth2-proxy asserts through Traefik ForwardAuth.
 *
 * Trust chain (any broken link makes these headers a spoofing vector):
 *  1. the Mautic container publishes no port; Traefik is the only way in;
 *  2. every Mautic router runs strip-auth-headers before mpass-auth, so a client cannot inject
 *     X-Auth-Request-*;
 *  3. oauth2-proxy validates the upstream session and injects the headers on every request;
 *  4. the protected router adds X-Mpass-Edge-Secret = MPASS_EDGE_SECRET, and every Mautic router
 *     strips a client-sent copy. Link 1 only holds for the outside world: other containers on the
 *     same networks, and Mautic's own outbound HTTP (campaign webhooks, form repost), can reach
 *     Apache directly with any headers. So the identity headers are trusted only on a request that
 *     carries the edge secret; without it they are treated as absent.
 *
 * All settings come from the process env (or a dotenv file) via %env(default::…)%, resolved when
 * the service is built for a request, never from a Mautic config key and never at container compile
 * time. See sso-rules-moneta openspec/changes/add-mautic-to-sso/design.md §2.
 *
 * AUTH_TYPE is also a CGI meta-variable (RFC 3875 §4.1.1). Symfony's %env()% reads $_ENV, then
 * $_SERVER, then getenv(), and app/config/bootstrap.php does `$_SERVER += $_ENV`, so a web server
 * that sets $_SERVER['AUTH_TYPE'] itself (HTTP auth configured in the server) would override the
 * flag. That fails towards non-SSO mode, never towards trusting headers; the image's Apache config
 * configures no HTTP auth.
 */
final class ProxyIdentity
{
    public const EMAIL_HEADER = 'X-Auth-Request-Email';

    public const ACCESS_TOKEN_HEADER = 'X-Auth-Request-Access-Token';

    public const EDGE_SECRET_HEADER = 'X-Mpass-Edge-Secret';

    /** users.email / users.username are varchar(191). */
    private const MAX_EMAIL_LENGTH = 191;

    public function __construct(
        private readonly ?string $authType,
        private readonly ?string $defaultEmailDomain,
        private readonly ?string $corporateId,
        private readonly ?string $edgeSecret = null,
    ) {
    }

    public function isSso(): bool
    {
        return 'SSO' === $this->authType;
    }

    public static function normalise(?string $value): string
    {
        return mb_strtolower(trim((string) $value));
    }

    /**
     * The normalised asserted identity, '' when absent or whitespace-only (absence is not a logout
     * signal). Only X-Auth-Request-Email is read; X-Auth-Request-User (the Cognito sub) never is.
     */
    public function asserted(Request $request): string
    {
        return $this->fromEdge($request) ? self::normalise($request->headers->get(self::EMAIL_HEADER)) : '';
    }

    /**
     * True only when the request came through the protected Traefik router: it carries the edge
     * secret, compared in constant time. An unset or short MPASS_EDGE_SECRET trusts nothing (the
     * image refuses to start under SSO without one).
     */
    public function fromEdge(Request $request): bool
    {
        $secret = (string) $this->edgeSecret;

        return strlen($secret) >= 32
            && hash_equals($secret, (string) $request->headers->get(self::EDGE_SECRET_HEADER, ''));
    }

    /**
     * The email the asserted identity resolves to, or null when it is asserted but unresolvable
     * (not email-shaped and DEFAULT_EMAIL_DOMAIN unset, or too long). Never guesses a domain.
     */
    public function resolve(string $asserted): ?string
    {
        if ('' === $asserted) {
            return null;
        }

        if (str_contains($asserted, '@')) {
            $email = self::isEmailShaped($asserted) ? $asserted : null;
        } else {
            $domain = self::normalise($this->defaultEmailDomain);
            $email  = '' === $domain ? null : $asserted.'@'.$domain;
        }

        return null !== $email && strlen($email) <= self::MAX_EMAIL_LENGTH ? $email : null;
    }

    /**
     * O(n) shape check, deliberately not a regex (proxy-auth-middleware §"email-shape detection").
     */
    public static function isEmailShaped(string $value): bool
    {
        $at = strpos($value, '@');
        if (false === $at || 0 === $at) {
            return false;
        }
        $dot = strpos($value, '.', $at + 1);

        return false !== $dot && $dot > $at + 1;
    }

    /**
     * Corporate-tenant binding (audit row 22). No-op when SMB_CORPORATE_ID is unset. Otherwise the
     * access token is decoded WITHOUT verification (oauth2-proxy already validated it) and BOTH
     * claims must match strictly. Absent or undecodable token → false; never throws.
     */
    public function corporateOk(Request $request): bool
    {
        $required = trim((string) $this->corporateId);
        if ('' === $required) {
            return true;
        }

        if (!$this->fromEdge($request)) {
            return false;
        }
        $claims = self::decodeJwtPayload((string) $request->headers->get(self::ACCESS_TOKEN_HEADER, ''));

        return null !== $claims
            && 'true' === ($claims['custom:is_corporate'] ?? null)
            && $required === ($claims['custom:corporate_id'] ?? null);
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function decodeJwtPayload(string $token): ?array
    {
        $parts = explode('.', trim($token));
        if (3 !== count($parts) || '' === $parts[1]) {
            return null;
        }

        $json = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if (false === $json) {
            return null;
        }

        try {
            $claims = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($claims) ? $claims : null;
    }
}
