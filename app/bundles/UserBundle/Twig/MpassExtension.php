<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Twig;

use Mautic\UserBundle\Security\Mpass\ProxyIdentity;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Exposes the mPass SSO flag and portal URL to templates. Rendered per request, never baked into
 * built assets (audit row 5).
 */
final class MpassExtension extends AbstractExtension
{
    public function __construct(
        private readonly ProxyIdentity $identity,
        private readonly ?string $portalUrl,
    ) {
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('mpassSsoEnabled', fn (): bool => $this->identity->isSso()),
            // '' unless an absolute http(s) URL: the menu then keeps the logout route, whose guard
            // logs the bad value and shows the static page.
            new TwigFunction('mpassPortalUrl', fn (): string => (string) ProxyIdentity::portalUrl($this->portalUrl)),
        ];
    }
}
