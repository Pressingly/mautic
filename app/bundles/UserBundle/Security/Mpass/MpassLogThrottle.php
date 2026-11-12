<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * Logs an mPass event at most once per WINDOW_SECONDS for the same level, message and throttle key,
 * so keep-alive XHRs and retries cannot flood the log with one line per request. For requests that
 * did not come through the edge the key must be the socket address: their headers are the
 * caller's to choose.
 */
final readonly class MpassLogThrottle
{
    public const WINDOW_SECONDS = 60;

    public function __construct(
        private LoggerInterface $logger,
        private CacheItemPoolInterface $cache,
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context, string $throttleKey): void
    {
        $item = $this->cache->getItem('mpass_log.'.hash('sha256', implode("\0", [$level, $message, $throttleKey])));
        if ($item->isHit()) {
            return;
        }
        $this->cache->save($item->set(true)->expiresAfter(self::WINDOW_SECONDS));
        $this->logger->log($level, $message, $context);
    }
}
