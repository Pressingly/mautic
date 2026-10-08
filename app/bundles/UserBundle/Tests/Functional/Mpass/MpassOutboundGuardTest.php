<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use GuzzleHttp\RequestOptions;
use Mautic\FormBundle\EventListener\FormSubscriber;
use Mautic\LeadBundle\Entity\Lead;
use Mautic\UserBundle\Security\Mpass\MpassOutboundGuard;
use Mautic\WebhookBundle\Exception\PrivateAddressException;
use Mautic\WebhookBundle\Helper\CampaignHelper;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Review finding 2b: under SSO, admin-configured outbound HTTP cannot target the bundle's internal
 * network (where every app trusts X-Auth-Request-* from whoever reaches its port).
 */
final class MpassOutboundGuardTest extends AbstractMpassTestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function privateUrls(): iterable
    {
        yield 'loopback' => ['http://127.0.0.1/s/account'];
        yield 'localhost' => ['http://localhost:8080/'];
        yield 'rfc1918 10/8' => ['http://10.1.2.3/'];
        yield 'docker bridge 172.16/12' => ['http://172.20.0.5:80/api/v1/profile'];
        yield 'ipv6 loopback' => ['http://[::1]/'];
        yield 'link-local metadata' => ['http://169.254.169.254/latest/meta-data/'];
        yield 'not a url' => ['not a url'];
        // Round-2 review (R2-1): forms upstream's PrivateAddressChecker let through.
        yield 'ipv4-mapped loopback' => ['http://[::ffff:127.0.0.1]/'];
        yield 'ipv4-mapped docker bridge, hex form' => ['http://[::ffff:ac14:5]/'];
        yield 'ipv4-compatible loopback' => ['http://[::127.0.0.1]/'];
        yield '0.0.0.0' => ['http://0.0.0.0/'];
        yield 'ipv6 unspecified' => ['http://[::]/'];
        yield 'cgnat 100.64/10' => ['http://100.64.1.1/'];
        yield 'documentation 192.0.2/24' => ['http://192.0.2.1/'];
        yield 'benchmarking 198.18/15' => ['http://198.18.0.1/'];
        yield 'multicast' => ['http://224.0.0.1/'];
        yield 'broadcast' => ['http://255.255.255.255/'];
        yield 'nat64 of loopback' => ['http://[64:ff9b::7f00:1]/'];
        yield 'unique local' => ['http://[fd00::1]/'];
        yield 'not http' => ['file:///etc/passwd'];
        yield 'gopher' => ['gopher://127.0.0.1:6379/_x'];
    }

    public function testHostnameResolvingToAPrivateAddressIsRefused(): void
    {
        $this->expectException(PrivateAddressException::class);
        $this->guard(['172.20.0.5'])->check('https://innocent.example.test/hook');
    }

    public function testAnyPrivateAnswerAmongPublicOnesIsRefused(): void
    {
        $this->expectException(PrivateAddressException::class);
        $this->guard(['93.184.216.34', '::ffff:10.0.0.7'])->check('https://mixed.example.test/hook');
    }

    public function testUnresolvableHostIsRefused(): void
    {
        $this->expectException(PrivateAddressException::class);
        $this->guard([])->check('https://nowhere.example.test/hook');
    }

    public function testConnectionIsPinnedToTheCheckedAddress(): void
    {
        $this->assertSame([RequestOptions::ALLOW_REDIRECTS => false, 'curl' => [CURLOPT_RESOLVE => ['hooks.example.test:443:93.184.216.34']]], $this->guard(['93.184.216.34'])->check('https://hooks.example.test/hook'));
        $this->assertSame(['hooks.example.test:8080:[2606:2800:220:1:248:1893:25c8:1946]'], $this->guard(['2606:2800:220:1:248:1893:25c8:1946'])->check('http://hooks.example.test:8080/')['curl'][CURLOPT_RESOLVE]);
    }

    /**
     * @param array<int, string> $answers what DNS returns for any host
     */
    private function guard(array $answers): MpassOutboundGuard
    {
        return new MpassOutboundGuard(
            self::getContainer()->get(\Mautic\UserBundle\Security\Mpass\ProxyIdentity::class),
            self::getContainer()->get(\Mautic\CoreBundle\Helper\CoreParametersHelper::class),
            static fn (string $host): array => $answers,
        );
    }

    #[DataProvider('privateUrls')]
    public function testPrivateTargetsAreRefusedUnderSso(string $url): void
    {
        $this->expectException(PrivateAddressException::class);
        self::getContainer()->get(MpassOutboundGuard::class)->check($url);
    }

    public function testPublicTargetIsAllowedWithoutRedirects(): void
    {
        $this->assertSame([RequestOptions::ALLOW_REDIRECTS => false], self::getContainer()->get(MpassOutboundGuard::class)->check('http://93.184.216.34/hook'));
    }

    public function testUpstreamAllowListIsHonoured(): void
    {
        $this->configParams['webhook_allowed_private_addresses'] = ['10.1.2.3'];
        $this->restart();

        $this->assertSame([RequestOptions::ALLOW_REDIRECTS => false], self::getContainer()->get(MpassOutboundGuard::class)->check('http://10.1.2.3/hook'));
    }

    public function testUpstreamBehaviourWithoutSso(): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);

        $this->assertSame([], self::getContainer()->get(MpassOutboundGuard::class)->check('http://127.0.0.1/'));
    }

    public function testCampaignWebhookToAPrivateAddressIsNeverSent(): void
    {
        $this->expectException(PrivateAddressException::class);

        self::getContainer()->get(CampaignHelper::class)->fireWebhook([
            'url'             => 'http://127.0.0.1:1/s/account',
            'method'          => 'post',
            'timeout'         => 1,
            'headers'         => ['list' => ['X-Auth-Request-Email' => 'admin@example.com']],
            'additional_data' => ['list' => []],
        ], new Lead());
    }

    public function testFormRepostAndCampaignWebhookAreWiredToTheGuard(): void
    {
        foreach ([CampaignHelper::class, FormSubscriber::class] as $service) {
            $property = new \ReflectionProperty($service, 'mpassOutboundGuard');
            $this->assertInstanceOf(MpassOutboundGuard::class, $property->getValue(self::getContainer()->get($service)), $service);
        }
    }
}
