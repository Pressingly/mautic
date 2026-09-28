<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use GuzzleHttp\RequestOptions;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\CoreBundle\Helper\PrivateAddressChecker;
use Mautic\WebhookBundle\Exception\PrivateAddressException;

/**
 * Keeps Mautic's admin-configured outbound HTTP (campaign "Send a webhook", form "repost") off
 * private and loopback addresses under AUTH_TYPE=SSO.
 *
 * Why only under SSO: behind the mPass edge, every app on the bundle's shared networks trusts
 * X-Auth-Request-* from whoever reaches its port. A webhook pointed at http://<app>:<port> with
 * forged identity headers would be a request "from the edge" to that app, i.e. an impersonation
 * of any user in any bundle app, configured by any Mautic user who may edit a campaign or a form.
 * Without SSO that threat does not exist, and upstream deliberately lets these two features reach
 * internal hosts, so the fork leaves them as they are.
 *
 * Mirrors upstream's own webhook client (WebhookBundle/Http/Client.php), including its allow-list
 * `webhook_allowed_private_addresses`, and adds allow_redirects=false: a public URL that
 * redirects to a private one would otherwise pass the check.
 *
 * Known ceiling: the check resolves the host, then Guzzle resolves it again to connect (DNS
 * rebinding window). Closing it needs a pinned-IP transport (CURLOPT_RESOLVE); the edge secret
 * (ProxyIdentity::fromEdge) still keeps a forged request from authenticating to Mautic itself.
 */
final class MpassOutboundGuard
{
    public function __construct(
        private readonly ProxyIdentity $identity,
        private readonly PrivateAddressChecker $privateAddressChecker,
        private readonly CoreParametersHelper $coreParametersHelper,
    ) {
    }

    /**
     * @return array<string, mixed> Guzzle request options to merge into the outbound request
     *
     * @throws PrivateAddressException when SSO is on and the URL targets a disallowed address
     */
    public function check(string $url): array
    {
        if (!$this->identity->isSso()) {
            return [];
        }

        $this->privateAddressChecker->setAllowedPrivateAddresses(
            (array) ($this->coreParametersHelper->get('webhook_allowed_private_addresses') ?? [])
        );

        try {
            $allowed = $this->privateAddressChecker->isAllowedUrl($url);
        } catch (\InvalidArgumentException) {
            $allowed = false;
        }
        if (!$allowed) {
            throw new PrivateAddressException();
        }

        return [RequestOptions::ALLOW_REDIRECTS => false];
    }
}
