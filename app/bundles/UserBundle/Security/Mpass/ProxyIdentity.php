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
 *  4. REQUIRED: the protected router adds X-Mpass-Edge-Secret (MPASS_EDGE_SECRET), and every
 *     Mautic router strips a client-sent copy. Link 1 only holds for the outside world: other
 *     containers on the same networks can reach Apache directly with any headers. Identity headers
 *     are trusted only on a request that carries the secret; with no usable secret (unset, a
 *     CHANGE_ME_ placeholder, or shorter than 32 characters) nothing is trusted, so nobody can sign
 *     in through mPass (fail closed);
 *  5. with SMB_CORPORATE_ID set, the forwarded token's signature, issuer, expiry and audience are
 *     verified (MpassTokenVerifier) before its corporate claims are believed.
 *
 * All settings come from the process env (or a dotenv file) via %env(default::…)%, resolved when
 * the service is built for a request, never from a Mautic config key and never at container compile
 * time. See doc/mpass_sso.md.
 *
 * AUTH_TYPE is also a CGI meta-variable (RFC 3875 §4.1.1). Symfony's %env()% reads $_ENV, then
 * $_SERVER, then getenv(), and app/config/bootstrap.php does `$_SERVER += $_ENV`, so a web server
 * that sets $_SERVER['AUTH_TYPE'] itself (HTTP auth configured in the server) would override the
 * flag. That fails towards non-SSO mode, never towards trusting headers; the image's Apache config
 * configures no HTTP auth.
 */
final readonly class ProxyIdentity
{
    public const EMAIL_HEADER = 'X-Auth-Request-Email';

    public const ACCESS_TOKEN_HEADER = 'X-Auth-Request-Access-Token';

    public const EDGE_SECRET_HEADER = 'X-Mpass-Edge-Secret';

    public const MIN_EDGE_SECRET_LENGTH = 32;

    /** Read only to name the caller in logs; never an identity source. */
    private const MPASS_ID_HEADERS = ['X-Auth-Request-User', 'X-Auth-Request-Preferred-Username'];

    private const PLACEHOLDER_PREFIX = 'CHANGE_ME_';

    /** users.email / users.username are varchar(191). */
    private const MAX_EMAIL_LENGTH = 191;

    public function __construct(
        private ?string $authType,
        private ?string $defaultEmailDomain,
        private ?string $corporateId,
        private MpassTokenVerifier $tokenVerifier,
        private ?string $edgeSecret = null,
        private ?string $edgeSecretFile = null,
        private ?string $allowAnyTenant = null,
    ) {
    }

    /** A setting's value, or '' when it is unset or still an .env.example placeholder. */
    public static function configured(?string $value): string
    {
        $value = trim((string) $value);

        return str_starts_with($value, self::PLACEHOLDER_PREFIX) ? '' : $value;
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
     * Whether the request came through the protected Traefik router: it carries the configured edge
     * secret, compared in constant time. Without a usable secret nothing is trusted (fail closed);
     * the image logs that at startup.
     *
     * The image passes the secret as a FILE (MPASS_EDGE_SECRET_FILE) and removes MPASS_EDGE_SECRET
     * from Apache's environment, so phpinfo()/environment dumps cannot show it. MPASS_EDGE_SECRET
     * itself is still honoured for tests and a source-mounted devstack.
     */
    public function fromEdge(Request $request): bool
    {
        $secret = $this->edgeSecret();

        return self::isUsableEdgeSecret($secret)
            && hash_equals($secret, (string) $request->headers->get(self::EDGE_SECRET_HEADER, ''));
    }

    /**
     * Whether the request asserts an mPass identity at all, trusted or not: for the warning when
     * one arrives without the edge secret.
     */
    public static function carriesIdentity(Request $request): bool
    {
        return '' !== trim((string) $request->headers->get(self::EMAIL_HEADER, ''));
    }

    public function hasUsableEdgeSecret(): bool
    {
        return self::isUsableEdgeSecret($this->edgeSecret());
    }

    public static function isUsableEdgeSecret(string $secret): bool
    {
        return strlen($secret) >= self::MIN_EDGE_SECRET_LENGTH;
    }

    /**
     * The caller's mPass id for log lines: the first X-Auth-Request-User or -Preferred-Username value
     * that is not an email, else '-'. Never the email header.
     */
    public static function mpassIdForLogs(Request $request): string
    {
        foreach (self::MPASS_ID_HEADERS as $header) {
            $value = trim((string) $request->headers->get($header, ''));
            if ('' !== $value && !str_contains($value, '@')) {
                return $value;
            }
        }

        return '-';
    }

    /**
     * LOGOUT_REDIRECT_URL when it is an absolute http(s) URL, else null: the caller logs and leaves
     * the link alone rather than redirecting to a relative or script URL.
     */
    public static function portalUrl(?string $value): ?string
    {
        $value  = trim((string) $value);
        $scheme = strtolower((string) parse_url($value, PHP_URL_SCHEME));

        return in_array($scheme, ['http', 'https'], true) && '' !== (string) parse_url($value, PHP_URL_HOST) ? $value : null;
    }

    private function edgeSecret(): string
    {
        $secret = self::configured($this->edgeSecret);
        if ('' === $secret && null !== $this->edgeSecretFile && '' !== $this->edgeSecretFile && is_readable($this->edgeSecretFile)) {
            $secret = self::configured((string) file_get_contents($this->edgeSecretFile));
        }

        return $secret;
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
     * Corporate-tenant binding (audit row 22): null when the request may proceed, else the refusal.
     * The forwarded token is verified first (signature, issuer, expiry, audience), then BOTH claims
     * must match strictly. Never throws.
     *
     * Fails closed: with SMB_CORPORATE_ID unset, every principal in the Cognito pool would be
     * admitted, so that is allowed only when the deployment says so with MPASS_ALLOW_ANY_TENANT=1
     * (the same opt-in the image's entrypoint requires), and then no token is read or fetched.
     * Stricter than the contract, which skips the check when SMB_CORPORATE_ID is unset; recorded as
     * a trade-off in doc/mpass_sso.md.
     */
    public function corporateRefusal(Request $request): ?MpassRefusalException
    {
        $required = self::configured($this->corporateId);
        if ('' === $required) {
            return '1' === trim((string) $this->allowAnyTenant) ? null : self::refusal(MpassRefusalException::CORPORATE, 'no_tenant_binding');
        }
        if (!$this->fromEdge($request)) {
            return self::refusal(MpassRefusalException::CORPORATE, 'not_from_edge');
        }

        $token = trim((string) $request->headers->get(self::ACCESS_TOKEN_HEADER, ''));
        if ('' === $token) {
            return self::refusal(MpassRefusalException::CORPORATE, MpassTokenException::MISSING);
        }

        try {
            $claims = $this->verifiedClaims($token);
        } catch (MpassTokenException $e) {
            return self::refusal(MpassRefusalException::TOKEN, $e->reason);
        }

        return match (true) {
            'true' !== ($claims['custom:is_corporate'] ?? null)    => self::refusal(MpassRefusalException::CORPORATE, MpassRefusalException::NOT_CORPORATE),
            $required !== ($claims['custom:corporate_id'] ?? null) => self::refusal(MpassRefusalException::CORPORATE, MpassRefusalException::WRONG_ORGANIZATION),
            default                                                => null,
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function verifiedClaims(string $token): array
    {
        return $this->tokenVerifier->verify($token);
    }

    private static function refusal(string $reason, string $detail): MpassRefusalException
    {
        return new MpassRefusalException($reason, null, $detail);
    }
}
