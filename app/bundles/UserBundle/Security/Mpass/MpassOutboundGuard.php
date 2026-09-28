<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use GuzzleHttp\RequestOptions;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\WebhookBundle\Exception\PrivateAddressException;

/**
 * Keeps Mautic's admin-configured outbound HTTP that can carry arbitrary headers (campaign "Send a
 * webhook", form "repost") off internal and special-purpose addresses under AUTH_TYPE=SSO.
 *
 * Why only under SSO: behind the mPass edge, every app on the bundle's shared networks trusts
 * X-Auth-Request-* from whoever reaches its port. A webhook pointed at http://<app>:<port> with
 * forged identity headers would impersonate any user in any bundle app. Without SSO that threat
 * does not exist, and upstream deliberately lets these two features reach internal hosts.
 *
 * Self-contained on purpose: upstream's PrivateAddressChecker misses IPv4-mapped IPv6, 0.0.0.0/8,
 * 100.64.0.0/10 and other special-purpose ranges. The host is resolved ONCE; the URL is refused if
 * ANY resolved address (A and AAAA) is disallowed; the connection is pinned to the checked address
 * with CURLOPT_RESOLVE, so DNS cannot answer differently between check and connect (rebinding).
 * Redirects are not followed. Upstream's `webhook_allowed_private_addresses` allow-list (hosts, IPs
 * or CIDRs) still opts specific internal targets in.
 *
 * Other outbound HTTP in Mautic is not guarded here because it cannot carry arbitrary headers:
 * remote assets (Asset::buildRemoteCurl), AbstractIntegration::checkImageExists, the integrations'
 * HTTP factories, IP lookup services, Twilio and the Marketplace send fixed or credential headers
 * only. Upstream's own webhook client (WebhookBundle/Http/Client.php) already checks private
 * addresses. See sso-rules-moneta apps/mautic/security.md, round-2 review.
 */
final class MpassOutboundGuard
{
    /** IANA special-purpose and non-global ranges (RFC 6890 and successors), IPv4. */
    private const DENIED_V4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24',
        '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
        '224.0.0.0/4', '240.0.0.0/4',
    ];

    /** The same for IPv6. IPv4-mapped (::ffff:0:0/96) and -compatible (::/96) are unwrapped first. */
    private const DENIED_V6 = [
        '::/128', '::1/128', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32',
        '2002::/16', '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
    ];

    private readonly \Closure $resolver;

    public function __construct(
        private readonly ProxyIdentity $identity,
        private readonly CoreParametersHelper $coreParametersHelper,
        ?\Closure $resolver = null,
    ) {
        $this->resolver = $resolver ?? \Closure::fromCallable([self::class, 'resolve']);
    }

    /**
     * @return array<string, mixed> Guzzle request options to merge into the outbound request
     *
     * @throws PrivateAddressException when SSO is on and the URL is not allowed
     */
    public function check(string $url): array
    {
        if (!$this->identity->isSso()) {
            return [];
        }

        $parts = parse_url($url);
        if (false === $parts) {
            throw new PrivateAddressException('Only absolute http(s) URLs are allowed.');
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host   = strtolower(trim((string) ($parts['host'] ?? ''), '[]'));
        if (!in_array($scheme, ['http', 'https'], true) || '' === $host) {
            throw new PrivateAddressException('Only absolute http(s) URLs are allowed.');
        }
        $port    = (int) ($parts['port'] ?? ('https' === $scheme ? 443 : 80));
        $literal = false !== filter_var($host, FILTER_VALIDATE_IP);
        $ips     = $literal ? [$host] : array_values(($this->resolver)($host));
        if ([] === $ips) {
            throw new PrivateAddressException('The host does not resolve.');
        }

        $allowList = [];
        foreach ((array) ($this->coreParametersHelper->get('webhook_allowed_private_addresses') ?? []) as $entry) {
            $allowList[] = strtolower(trim((string) $entry));
        }
        foreach ($ips as $ip) {
            if (self::isDenied((string) $ip) && !in_array($host, $allowList, true) && !self::inAny((string) $ip, $allowList)) {
                throw new PrivateAddressException();
            }
        }

        $options = [RequestOptions::ALLOW_REDIRECTS => false];
        if (!$literal) {
            // Connect to exactly the address that was checked.
            $first           = (string) $ips[0];
            $pinned          = str_contains($first, ':') ? '['.$first.']' : $first;
            $options['curl'] = [CURLOPT_RESOLVE => [$host.':'.$port.':'.$pinned]];
        }

        return $options;
    }

    /**
     * True for any address outside the public unicast space, and for anything that is not an IP.
     * IPv4-mapped/compatible IPv6 (::ffff:a.b.c.d, ::a.b.c.d, any notation) is judged as the IPv4
     * address it carries.
     */
    public static function isDenied(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if (false === $bin) {
            return true;
        }
        if (16 === strlen($bin)) {
            $prefix = substr($bin, 0, 12);
            $tail   = substr($bin, 12);
            $mapped = $prefix === str_repeat("\0", 10)."\xff\xff";
            $compat = $prefix === str_repeat("\0", 12) && "\0\0\0\0" !== $tail && "\0\0\0\1" !== $tail;
            if ($mapped || $compat) {
                return self::isDenied((string) inet_ntop($tail));
            }

            return self::inAny($ip, self::DENIED_V6);
        }

        return self::inAny($ip, self::DENIED_V4);
    }

    /**
     * @param array<int, string> $ranges IPs or CIDRs; anything else is ignored
     */
    private static function inAny(string $ip, array $ranges): bool
    {
        $bin = @inet_pton($ip);
        if (false === $bin) {
            return false;
        }
        foreach ($ranges as $range) {
            $pieces = explode('/', $range, 2);
            $netBin = @inet_pton($pieces[0]);
            if (false === $netBin || strlen($netBin) !== strlen($bin)) {
                continue;
            }
            $bits = isset($pieces[1]) ? (int) $pieces[1] : 8 * strlen($bin);
            $full = intdiv($bits, 8);
            if (substr($bin, 0, $full) !== substr($netBin, 0, $full)) {
                continue;
            }
            $rest = $bits % 8;
            if (0 === $rest) {
                return true;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if (0 === ((ord($bin[$full]) ^ ord($netBin[$full])) & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every A and AAAA address of $host, resolved once.
     *
     * @return array<int, string>
     */
    private static function resolve(string $host): array
    {
        $ips     = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        foreach (is_array($records) ? $records : [] as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($ip) && '' !== $ip) {
                $ips[] = $ip;
            }
        }
        if ([] === $ips) {
            $v4  = @gethostbynamel($host);
            $ips = is_array($v4) ? $v4 : [];
        }

        return array_values(array_unique($ips));
    }
}
