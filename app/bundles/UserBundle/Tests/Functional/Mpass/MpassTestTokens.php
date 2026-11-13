<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use Firebase\JWT\JWT;

/**
 * Test-only mPass issuers: an RS256 key pair, its JWKS, and tokens shaped like the ones
 * oauth2-proxy forwards (a Cognito access token, a re-signed id_token).
 */
final class MpassTestTokens
{
    public const ISSUER       = 'https://cognito-idp.test-region-1.amazonaws.com/test-region-1_pool';
    public const PROXY_ISSUER = 'https://mpass-proxy.example.test';
    public const CLIENT_ID    = 'mpass-test-client';
    public const KID          = 'mpass-test-kid';

    /** @var array<string, string> */
    private static array $privateKeys = [];

    public static function privateKey(string $name = 'issuer'): string
    {
        return self::$privateKeys[$name] ??= self::generatePrivateKey();
    }

    public static function jwksUrl(string $issuer = self::ISSUER): string
    {
        return $issuer.'/.well-known/jwks.json';
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public static function jwks(string $kid = self::KID, string $keyName = 'issuer'): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private(self::privateKey($keyName)));

        return ['keys' => [[
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $kid,
            'n'   => JWT::urlsafeB64Encode($details['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($details['rsa']['e']),
        ]]];
    }

    /**
     * A Cognito-shaped access token. A claim set to null is left out.
     *
     * @param array<string, mixed> $claims
     */
    public static function accessToken(array $claims = [], string $keyName = 'issuer', string $kid = self::KID): string
    {
        return self::sign(self::withDefaults($claims + ['token_use' => 'access', 'client_id' => self::CLIENT_ID]), $keyName, $kid);
    }

    /**
     * An id_token re-signed by mpass-auth-proxy. A claim set to null is left out.
     *
     * @param array<string, mixed> $claims
     */
    public static function idToken(array $claims = [], string $keyName = 'issuer', string $kid = self::KID): string
    {
        return self::sign(self::withDefaults($claims + ['iss' => self::PROXY_ISSUER, 'token_use' => 'id', 'aud' => self::CLIENT_ID]), $keyName, $kid);
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function unsigned(array $header, array $claims): string
    {
        return JWT::urlsafeB64Encode((string) json_encode($header)).'.'.JWT::urlsafeB64Encode((string) json_encode(self::withDefaults($claims + ['token_use' => 'access', 'client_id' => self::CLIENT_ID]))).'.';
    }

    /**
     * Signed HS256 with the issuer's public key as the HMAC secret: the algorithm-confusion forgery.
     *
     * @param array<string, mixed> $claims
     */
    public static function hs256WithPublicKey(array $claims = []): string
    {
        $public = openssl_pkey_get_details(openssl_pkey_get_private(self::privateKey()))['key'];

        return JWT::encode(self::withDefaults($claims + ['token_use' => 'access', 'client_id' => self::CLIENT_ID]), $public, 'HS256', self::KID);
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private static function withDefaults(array $claims): array
    {
        $now = time();

        return array_filter($claims + ['iss' => self::ISSUER, 'iat' => $now, 'exp' => $now + 3600, 'sub' => 'mpass-test-sub'], static fn ($value): bool => null !== $value);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function sign(array $claims, string $keyName, string $kid): string
    {
        return JWT::encode($claims, self::privateKey($keyName), 'RS256', $kid);
    }

    private static function generatePrivateKey(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }
}
