<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Logs an mPass event at most once per WINDOW_SECONDS for the same level, message and throttle key,
 * so keep-alive XHRs and retries cannot flood the log with one line per request. For requests that
 * did not come through the edge the key must be the socket address: their headers are the
 * caller's to choose.
 *
 * Errors are also written to the process error log (Apache's ErrorLog is stderr in the image), so a
 * deployment fault such as an unusable edge secret shows in `docker logs`, not only in var/logs.
 */
final readonly class MpassLogThrottle
{
    public const WINDOW_SECONDS = 60;

    private const STDERR_LEVELS = [LogLevel::ERROR, LogLevel::CRITICAL, LogLevel::ALERT, LogLevel::EMERGENCY];

    /** @var \Closure(string): mixed */
    private \Closure $stderr;

    /**
     * @param (\Closure(string): mixed)|callable-string $stderr where error-level lines also go
     */
    public function __construct(
        private LoggerInterface $logger,
        private CacheItemPoolInterface $cache,
        \Closure|string $stderr = 'error_log',
    ) {
        $this->stderr = \Closure::fromCallable($stderr);
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
        if (in_array($level, self::STDERR_LEVELS, true)) {
            ($this->stderr)('mautic '.$level.': '.$message.' '.json_encode($context, JSON_UNESCAPED_SLASHES));
        }
    }
}
