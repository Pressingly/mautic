<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Unit\Security\Mpass;

use Firebase\JWT\JWT;
use Mautic\UserBundle\Security\Mpass\MpassJwks;
use Mautic\UserBundle\Security\Mpass\MpassTokenException;
use Mautic\UserBundle\Security\Mpass\MpassTokenVerifier;
use Mautic\UserBundle\Tests\Functional\Mpass\MpassTestTokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class MpassTokenVerifierTest extends TestCase
{
    /** @var list<string> */
    private array $requestedUrls = [];

    /** @var array<string, callable(): MockResponse> */
    private array $responses = [];

    private ArrayAdapter $cache;

    protected function setUp(): void
    {
        $this->cache     = new ArrayAdapter();
        $this->responses = [
            MpassTestTokens::jwksUrl()                             => fn (): MockResponse => self::json(MpassTestTokens::jwks()),
            MpassTestTokens::jwksUrl(MpassTestTokens::PROXY_ISSUER) => fn (): MockResponse => self::json(MpassTestTokens::jwks('proxy-kid', 'proxy')),
        ];
    }

    public function testValidCognitoAccessTokenIsAccepted(): void
    {
        $claims = $this->verifier()->verify(MpassTestTokens::accessToken(['custom:corporate_id' => 'acme-42']));

        $this->assertSame('acme-42', $claims['custom:corporate_id']);
        $this->assertSame([MpassTestTokens::jwksUrl()], $this->requestedUrls);
    }

    public function testValidReSignedIdTokenIsAcceptedAgainstItsOwnJwks(): void
    {
        $claims = $this->verifier()->verify(MpassTestTokens::idToken(['aud' => ['other', MpassTestTokens::CLIENT_ID]], 'proxy', 'proxy-kid'));

        $this->assertSame('id', $claims['token_use']);
        $this->assertSame([MpassTestTokens::jwksUrl(MpassTestTokens::PROXY_ISSUER)], $this->requestedUrls);
    }

    public function testExpiryWithinTheLeewayIsAccepted(): void
    {
        $this->verifier()->verify(MpassTestTokens::accessToken(['exp' => time() - 30]));
        $this->addToAssertionCount(1);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedTokens(): iterable
    {
        yield 'bad signature'           => [MpassTestTokens::accessToken([], 'attacker'), MpassTokenException::BAD_SIGNATURE];
        yield 'expired'                 => [MpassTestTokens::accessToken(['exp' => time() - 120]), MpassTokenException::EXPIRED];
        yield 'not yet valid'           => [MpassTestTokens::accessToken(['nbf' => time() + 600]), MpassTokenException::NOT_YET_VALID];
        yield 'wrong issuer'            => [MpassTestTokens::accessToken(['iss' => 'https://cognito-idp.test-region-1.amazonaws.com/other_pool']), MpassTokenException::UNTRUSTED_ISSUER];
        yield 'issuer trailing slash'   => [MpassTestTokens::accessToken(['iss' => MpassTestTokens::ISSUER.'/']), MpassTokenException::UNTRUSTED_ISSUER];
        yield 'missing issuer'          => [MpassTestTokens::accessToken(['iss' => null]), MpassTokenException::UNTRUSTED_ISSUER];
        yield 'access, wrong client_id' => [MpassTestTokens::accessToken(['client_id' => 'another-client']), MpassTokenException::WRONG_AUDIENCE];
        yield 'access, aud only'        => [MpassTestTokens::accessToken(['client_id' => null, 'aud' => MpassTestTokens::CLIENT_ID]), MpassTokenException::WRONG_AUDIENCE];
        yield 'id, wrong aud'           => [MpassTestTokens::idToken(['aud' => 'another-client'], 'proxy', 'proxy-kid'), MpassTokenException::WRONG_AUDIENCE];
        yield 'unknown token_use'       => [MpassTestTokens::accessToken(['token_use' => 'refresh']), MpassTokenException::WRONG_AUDIENCE];
        yield 'missing token_use'       => [MpassTestTokens::accessToken(['token_use' => null]), MpassTokenException::MISSING_CLAIM];
        yield 'missing iat'             => [MpassTestTokens::accessToken(['iat' => null]), MpassTokenException::MISSING_CLAIM];
        yield 'missing exp'             => [MpassTestTokens::accessToken(['exp' => null]), MpassTokenException::MISSING_CLAIM];
        yield 'alg none'                => [MpassTestTokens::unsigned(['alg' => 'none', 'kid' => MpassTestTokens::KID], []), MpassTokenException::UNSUPPORTED_ALGORITHM];
        yield 'HS256 with public key'   => [MpassTestTokens::hs256WithPublicKey(), MpassTokenException::UNSUPPORTED_ALGORITHM];
        yield 'no kid'                  => [MpassTestTokens::unsigned(['alg' => 'RS256'], []), MpassTokenException::MALFORMED];
        yield 'unknown kid'             => [MpassTestTokens::accessToken([], 'issuer', 'rotated-away'), MpassTokenException::UNKNOWN_SIGNING_KEY];
        yield 'proxy token, Cognito key' => [MpassTestTokens::idToken([], 'issuer'), MpassTokenException::UNKNOWN_SIGNING_KEY];
        yield 'empty'                   => ['', MpassTokenException::MISSING];
        yield 'not a JWT'               => ['not-a-jwt', MpassTokenException::MALFORMED];
        yield 'bad base64'              => ['a.!!!.c', MpassTokenException::MALFORMED];
        yield 'payload not an object'   => [JWT::urlsafeB64Encode('{"alg":"RS256","kid":"k"}').'.'.JWT::urlsafeB64Encode('"a string"').'.c', MpassTokenException::MALFORMED];
    }

    #[DataProvider('rejectedTokens')]
    public function testRejectedTokens(string $token, string $reason): void
    {
        $this->assertRejected($reason, $this->verifier(), $token);
    }

    public function testUnconfiguredVerifierRejectsEverything(): void
    {
        $this->assertRejected(MpassTokenException::VERIFIER_UNCONFIGURED, $this->verifier(clientId: ''), MpassTestTokens::accessToken());
        $this->assertRejected(MpassTokenException::VERIFIER_UNCONFIGURED, $this->verifier(cognitoIssuer: 'CHANGE_ME_ISSUER', proxyIssuer: ''), MpassTestTokens::accessToken());
        $this->assertSame([], $this->requestedUrls, 'nothing fetched');
    }

    public function testJwksIsCachedPerIssuer(): void
    {
        $verifier = $this->verifier();
        $verifier->verify(MpassTestTokens::accessToken());
        $this->verifier()->verify(MpassTestTokens::accessToken());

        $this->assertCount(1, $this->requestedUrls, 'a new verifier reuses the cache pool, as the next PHP request would');
    }

    public function testUnknownKidRefetchesOnlyOnceTheCachedSetIsOldEnough(): void
    {
        $this->verifier()->verify(MpassTestTokens::accessToken());
        $this->assertRejected(MpassTokenException::UNKNOWN_SIGNING_KEY, $this->verifier(), MpassTestTokens::accessToken([], 'issuer', 'rotated-in'));
        $this->assertCount(1, $this->requestedUrls, 'a fresh set is not refetched for an unknown kid');
    }

    /**
     * @return iterable<string, array{callable(): MockResponse}>
     */
    public static function jwksFailures(): iterable
    {
        yield 'HTTP 500'       => [fn (): MockResponse => new MockResponse('oops', ['http_code' => 500])];
        yield 'redirect'       => [fn (): MockResponse => new MockResponse('', ['http_code' => 302, 'response_headers' => ['Location' => 'http://169.254.169.254/']])];
        yield 'not JSON'       => [fn (): MockResponse => new MockResponse('<html>', ['response_headers' => ['Content-Type' => 'application/json']])];
        yield 'no keys'        => [fn (): MockResponse => self::json(['keys' => []])];
        yield 'garbage key'    => [fn (): MockResponse => self::json(['keys' => [['kty' => 'RSA', 'kid' => MpassTestTokens::KID]]])];
        yield 'timeout'        => [fn (): MockResponse => throw new TransportException('Idle timeout reached')];
    }

    #[DataProvider('jwksFailures')]
    public function testJwksFailureRejectsAndBacksOff(callable $failure): void
    {
        $this->responses[MpassTestTokens::jwksUrl()] = $failure;

        $this->assertRejected(MpassTokenException::JWKS_UNAVAILABLE, $this->verifier(), MpassTestTokens::accessToken());
        $this->assertRejected(MpassTokenException::JWKS_UNAVAILABLE, $this->verifier(), MpassTestTokens::accessToken());
        $this->assertCount(1, $this->requestedUrls, 'the second request is inside the backoff window');

        $this->verifier()->verify(MpassTestTokens::idToken([], 'proxy', 'proxy-kid'));
        $this->assertCount(2, $this->requestedUrls, 'the backoff is per issuer');
    }

    public function testFetchIsBoundedAndDoesNotFollowRedirects(): void
    {
        $options = [];
        $client  = new MockHttpClient(function (string $method, string $url, array $requestOptions) use (&$options): MockResponse {
            $options = $requestOptions;

            return self::json(MpassTestTokens::jwks());
        });
        (new MpassTokenVerifier(new MpassJwks($client, $this->cache), MpassTestTokens::ISSUER, null, null, null, MpassTestTokens::CLIENT_ID))
            ->verify(MpassTestTokens::accessToken());

        $this->assertEquals(MpassJwks::FETCH_TIMEOUT_SECONDS, $options['timeout']);
        $this->assertEquals(MpassJwks::FETCH_TIMEOUT_SECONDS, $options['max_duration']);
        $this->assertSame(0, $options['max_redirects']);
    }

    public function testLeewayIsRestored(): void
    {
        $before = JWT::$leeway;
        $this->assertRejected(MpassTokenException::BAD_SIGNATURE, $this->verifier(), MpassTestTokens::accessToken([], 'attacker'));
        $this->verifier()->verify(MpassTestTokens::accessToken());

        $this->assertSame($before, JWT::$leeway);
    }

    public function testTrustedIssuers(): void
    {
        $this->assertSame(
            ['https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc', 'https://proxy.example'],
            MpassTokenVerifier::trustedIssuers(null, 'eu-west-1', 'eu-west-1_abc', 'https://proxy.example/'),
        );
        $this->assertSame(
            ['https://issuer.example/pool'],
            MpassTokenVerifier::trustedIssuers(' https://issuer.example/pool/ ', 'eu-west-1', 'eu-west-1_abc', 'CHANGE_ME_LAUNCHPAD_OIDC_ISSUER_URL'),
        );
        $this->assertSame([], MpassTokenVerifier::trustedIssuers('', 'eu-west-1', '', null));
    }

    private function verifier(string $cognitoIssuer = MpassTestTokens::ISSUER, string $proxyIssuer = MpassTestTokens::PROXY_ISSUER, string $clientId = MpassTestTokens::CLIENT_ID): MpassTokenVerifier
    {
        $client = new MockHttpClient(function (string $method, string $url): MockResponse {
            $this->requestedUrls[] = $url;

            return ($this->responses[$url] ?? fn (): MockResponse => new MockResponse('', ['http_code' => 404]))();
        });

        return new MpassTokenVerifier(new MpassJwks($client, $this->cache), $cognitoIssuer, null, null, $proxyIssuer, $clientId);
    }

    private function assertRejected(string $reason, MpassTokenVerifier $verifier, string $token): void
    {
        try {
            $verifier->verify($token);
            $this->fail("expected {$reason}");
        } catch (MpassTokenException $e) {
            $this->assertSame($reason, $e->reason);
        }
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function json(array $body): MockResponse
    {
        return new MockResponse((string) json_encode($body), ['response_headers' => ['Content-Type' => 'application/json']]);
    }
}
