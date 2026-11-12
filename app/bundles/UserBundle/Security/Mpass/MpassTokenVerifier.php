<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;

/**
 * Verifies the mPass token oauth2-proxy forwards in X-Auth-Request-Access-Token before any of its
 * claims are believed.
 *
 * A browser session forwards the Cognito access token; a Bearer caller forwards its id_token, which
 * mpass-auth-proxy re-signs under its own issuer when email capture is on. Both issuers are trusted,
 * each against its own JWKS, and nothing else is. RS256 only.
 */
final readonly class MpassTokenVerifier
{
    public const ALGORITHM              = 'RS256';
    public const CLOCK_SKEW_LEEWAY      = 60;
    public const REQUIRED_CLAIMS        = ['exp', 'iat', 'iss', 'token_use'];

    /** @var list<string> */
    private array $issuers;

    private string $clientId;

    public function __construct(
        private MpassJwks $jwks,
        ?string $cognitoIssuerUrl = null,
        ?string $cognitoRegion = null,
        ?string $cognitoUserPoolId = null,
        ?string $tokenIssuerUrl = null,
        ?string $clientId = null,
    ) {
        $this->issuers  = self::trustedIssuers($cognitoIssuerUrl, $cognitoRegion, $cognitoUserPoolId, $tokenIssuerUrl);
        $this->clientId = ProxyIdentity::configured($clientId);
    }

    /**
     * MPASS_COGNITO_ISSUER_URL, else the issuer built from COGNITO_AWS_REGION and
     * COGNITO_USER_POOL_ID, plus MPASS_TOKEN_ISSUER_URL when set.
     *
     * @return list<string>
     */
    public static function trustedIssuers(?string $cognitoIssuerUrl, ?string $cognitoRegion, ?string $cognitoUserPoolId, ?string $tokenIssuerUrl): array
    {
        $cognito = rtrim(ProxyIdentity::configured($cognitoIssuerUrl), '/');
        if ('' === $cognito) {
            $region  = ProxyIdentity::configured($cognitoRegion);
            $poolId  = ProxyIdentity::configured($cognitoUserPoolId);
            $cognito = '' !== $region && '' !== $poolId ? "https://cognito-idp.{$region}.amazonaws.com/{$poolId}" : '';
        }

        return array_values(array_unique(array_filter([$cognito, rtrim(ProxyIdentity::configured($tokenIssuerUrl), '/')])));
    }

    public function isConfigured(): bool
    {
        return [] !== $this->issuers && '' !== $this->clientId;
    }

    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws MpassTokenException
     */
    public function verify(string $token): array
    {
        if (!$this->isConfigured()) {
            throw new MpassTokenException(MpassTokenException::VERIFIER_UNCONFIGURED);
        }
        $token = trim($token);
        if ('' === $token) {
            throw new MpassTokenException(MpassTokenException::MISSING);
        }

        [$header, $unverified] = self::unverifiedParts($token);
        if (self::ALGORITHM !== ($header['alg'] ?? null)) {
            throw new MpassTokenException(MpassTokenException::UNSUPPORTED_ALGORITHM);
        }
        $kid    = is_string($header['kid'] ?? null) ? $header['kid'] : '';
        $issuer = is_string($unverified['iss'] ?? null) ? $unverified['iss'] : '';
        if ('' === $kid) {
            throw new MpassTokenException(MpassTokenException::MALFORMED);
        }
        if (!in_array($issuer, $this->issuers, true)) {
            throw new MpassTokenException(MpassTokenException::UNTRUSTED_ISSUER);
        }

        $claims = $this->decode($token, $this->signingKey($issuer, $kid));
        self::assertRequiredClaims($claims, $issuer);
        if (!self::audienceMatches($claims, $this->clientId)) {
            throw new MpassTokenException(MpassTokenException::WRONG_AUDIENCE);
        }

        return $claims;
    }

    /**
     * Cognito access tokens name the client in client_id; id_tokens in aud.
     *
     * @param array<string, mixed> $claims
     */
    public static function audienceMatches(array $claims, string $clientId): bool
    {
        return match ($claims['token_use'] ?? null) {
            'access' => $clientId === ($claims['client_id'] ?? null),
            'id'     => in_array($clientId, (array) ($claims['aud'] ?? []), true),
            default  => false,
        };
    }

    private function signingKey(string $issuer, string $kid): Key
    {
        $key = $this->jwks->signingKeys($issuer, $kid)[$kid] ?? null;
        if (!$key instanceof Key || self::ALGORITHM !== $key->getAlgorithm()) {
            throw new MpassTokenException(MpassTokenException::UNKNOWN_SIGNING_KEY);
        }

        return $key;
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $token, Key $key): array
    {
        $leeway      = JWT::$leeway;
        JWT::$leeway = self::CLOCK_SKEW_LEEWAY; // php-jwt only takes leeway as a static
        try {
            return json_decode((string) json_encode(JWT::decode($token, $key)), true, 32, JSON_THROW_ON_ERROR);
        } catch (ExpiredException $e) {
            throw new MpassTokenException(MpassTokenException::EXPIRED, $e);
        } catch (BeforeValidException $e) {
            throw new MpassTokenException(MpassTokenException::NOT_YET_VALID, $e);
        } catch (SignatureInvalidException $e) {
            throw new MpassTokenException(MpassTokenException::BAD_SIGNATURE, $e);
        } catch (\UnexpectedValueException|\DomainException|\InvalidArgumentException|\JsonException $e) {
            throw new MpassTokenException(MpassTokenException::INVALID, $e);
        } finally {
            JWT::$leeway = $leeway;
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function assertRequiredClaims(array $claims, string $issuer): void
    {
        foreach (self::REQUIRED_CLAIMS as $claim) {
            if (!isset($claims[$claim])) {
                throw new MpassTokenException(MpassTokenException::MISSING_CLAIM);
            }
        }
        if ($issuer !== $claims['iss']) {
            throw new MpassTokenException(MpassTokenException::UNTRUSTED_ISSUER);
        }
    }

    /**
     * The header and payload, unverified: only used to pick the issuer and key to verify with.
     *
     * @return array{array<string, mixed>, array<string, mixed>}
     */
    private static function unverifiedParts(string $token): array
    {
        $segments = explode('.', $token);
        if (3 !== count($segments)) {
            throw new MpassTokenException(MpassTokenException::MALFORMED);
        }

        return [self::decodeSegment($segments[0]), self::decodeSegment($segments[1])];
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $segment): array
    {
        try {
            $decoded = json_decode(JWT::urlsafeB64Decode($segment), true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException|\InvalidArgumentException) {
            throw new MpassTokenException(MpassTokenException::MALFORMED);
        }

        return is_array($decoded) ? $decoded : throw new MpassTokenException(MpassTokenException::MALFORMED);
    }
}
