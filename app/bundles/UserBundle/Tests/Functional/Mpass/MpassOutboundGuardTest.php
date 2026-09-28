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
    }

    #[DataProvider('privateUrls')]
    public function testPrivateTargetsAreRefusedUnderSso(string $url): void
    {
        $this->expectException(PrivateAddressException::class);
        static::getContainer()->get(MpassOutboundGuard::class)->check($url);
    }

    public function testPublicTargetIsAllowedWithoutRedirects(): void
    {
        self::assertSame(
            [RequestOptions::ALLOW_REDIRECTS => false],
            static::getContainer()->get(MpassOutboundGuard::class)->check('http://93.184.216.34/hook')
        );
    }

    public function testUpstreamAllowListIsHonoured(): void
    {
        $this->configParams['webhook_allowed_private_addresses'] = ['10.1.2.3'];
        $this->restart();

        self::assertSame([RequestOptions::ALLOW_REDIRECTS => false], static::getContainer()->get(MpassOutboundGuard::class)->check('http://10.1.2.3/hook'));
    }

    public function testUpstreamBehaviourWithoutSso(): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);

        self::assertSame([], static::getContainer()->get(MpassOutboundGuard::class)->check('http://127.0.0.1/'));
    }

    public function testCampaignWebhookToAPrivateAddressIsNeverSent(): void
    {
        $this->expectException(PrivateAddressException::class);

        static::getContainer()->get(CampaignHelper::class)->fireWebhook([
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
            self::assertInstanceOf(MpassOutboundGuard::class, $property->getValue(static::getContainer()->get($service)), $service);
        }
    }
}
