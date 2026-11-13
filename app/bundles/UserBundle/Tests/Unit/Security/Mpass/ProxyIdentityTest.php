<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Unit\Security\Mpass;

use Mautic\UserBundle\Security\Mpass\MpassJwks;
use Mautic\UserBundle\Security\Mpass\MpassRefusalException;
use Mautic\UserBundle\Security\Mpass\MpassTokenException;
use Mautic\UserBundle\Security\Mpass\MpassTokenVerifier;
use Mautic\UserBundle\Security\Mpass\ProxyIdentity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpFoundation\Request;

final class ProxyIdentityTest extends TestCase
{
    private const SECRET = 'unit-edge-secret-0123456789abcdef0123456789';

    /**
     * @return iterable<string, array{?string, string, bool}>
     */
    public static function edgeCases(): iterable
    {
        yield 'matching secret'           => [self::SECRET, self::SECRET, true];
        yield 'wrong secret'              => [self::SECRET, 'wrong', false];
        yield 'no header'                 => [self::SECRET, '', false];
        yield 'unset trusts nothing'      => [null, '', false];
        yield 'empty trusts nothing'      => ['', '', false];
        yield 'short trusts nothing'      => ['short', 'short', false];
        yield 'placeholder trusts nothing' => ['CHANGE_ME_MAUTIC_EDGE_SECRET_0123456789abcdef', 'CHANGE_ME_MAUTIC_EDGE_SECRET_0123456789abcdef', false];
    }

    #[DataProvider('edgeCases')]
    public function testFromEdgeFailsClosed(?string $configured, string $sent, bool $trusted): void
    {
        $identity = new ProxyIdentity('SSO', null, null, $this->unconfiguredVerifier(), $configured);
        $request  = $this->request(['HTTP_X_AUTH_REQUEST_EMAIL' => 'alice@example.com', 'HTTP_X_MPASS_EDGE_SECRET' => $sent]);

        $this->assertSame($trusted, $identity->fromEdge($request));
        $this->assertSame($trusted ? 'alice@example.com' : '', $identity->asserted($request), 'untrusted headers are ignored');
    }

    public function testMpassIdForLogsNeverReturnsAnEmail(): void
    {
        $this->assertSame('mpass-123', ProxyIdentity::mpassIdForLogs($this->request(['HTTP_X_AUTH_REQUEST_USER' => 'mpass-123', 'HTTP_X_AUTH_REQUEST_EMAIL' => 'a@example.com'])));
        $this->assertSame('mpass-456', ProxyIdentity::mpassIdForLogs($this->request(['HTTP_X_AUTH_REQUEST_USER' => 'a@example.com', 'HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME' => 'mpass-456'])));
        $this->assertSame('-', ProxyIdentity::mpassIdForLogs($this->request(['HTTP_X_AUTH_REQUEST_EMAIL' => 'a@example.com'])));
    }

    public function testCorporateBindingWithoutAVerifierRefuses(): void
    {
        $identity = new ProxyIdentity('SSO', null, 'acme-42', $this->unconfiguredVerifier(), self::SECRET);
        $refusal  = $identity->corporateRefusal($this->request(['HTTP_X_MPASS_EDGE_SECRET' => self::SECRET, 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'a.b.c']));

        $this->assertInstanceOf(MpassRefusalException::class, $refusal);
        $this->assertSame(MpassRefusalException::TOKEN, $refusal->reason);
        $this->assertSame(MpassTokenException::VERIFIER_UNCONFIGURED, $refusal->detail);
    }

    public function testCorporateBindingOffOnlyWithTheOptIn(): void
    {
        $request = $this->request(['HTTP_X_MPASS_EDGE_SECRET' => self::SECRET]);

        $this->assertNotInstanceOf(MpassRefusalException::class, (new ProxyIdentity('SSO', null, null, $this->unconfiguredVerifier(), self::SECRET, null, '1'))->corporateRefusal($request));
        $this->assertSame('no_tenant_binding', (new ProxyIdentity('SSO', null, null, $this->unconfiguredVerifier(), self::SECRET))->corporateRefusal($request)?->detail);
    }

    /**
     * @param array<string, string> $server
     */
    private function request(array $server): Request
    {
        return Request::create('/s/account', 'GET', [], [], [], $server);
    }

    private function unconfiguredVerifier(): MpassTokenVerifier
    {
        return new MpassTokenVerifier(new MpassJwks(new MockHttpClient(), new ArrayAdapter()));
    }
}
