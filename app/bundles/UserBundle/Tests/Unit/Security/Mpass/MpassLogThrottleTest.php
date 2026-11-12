<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Unit\Security\Mpass;

use Mautic\UserBundle\Security\Mpass\MpassLogThrottle;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class MpassLogThrottleTest extends TestCase
{
    public function testTheSameEventIsLoggedOncePerWindowPerThrottleKey(): void
    {
        $logger   = self::recordingLogger();
        $throttle = new MpassLogThrottle($logger, new ArrayAdapter());

        foreach (['mpass-1', 'mpass-2', 'mpass-3'] as $spoofedId) {
            $throttle->log(LogLevel::WARNING, 'mPass identity headers ignored', ['mpass_id' => $spoofedId], '10.0.0.9');
        }
        $throttle->log(LogLevel::WARNING, 'mPass identity headers ignored', ['mpass_id' => 'mpass-1'], '10.0.0.10');
        $throttle->log(LogLevel::ERROR, 'mPass identity headers ignored', ['mpass_id' => 'mpass-1'], '10.0.0.9');

        $this->assertSame(
            [['warning', 'mpass-1'], ['warning', 'mpass-1'], ['error', 'mpass-1']],
            array_map(static fn (array $record): array => [$record[0], $record[2]['mpass_id']], $logger->records),
        );
    }

    public function testTheWindowExpires(): void
    {
        $logger   = self::recordingLogger();
        $cache    = new ArrayAdapter();
        $throttle = new MpassLogThrottle($logger, $cache);

        $throttle->log(LogLevel::ERROR, 'mPass SSO is off', ['mpass_id' => '-'], '10.0.0.9');
        $cache->clear();
        $throttle->log(LogLevel::ERROR, 'mPass SSO is off', ['mpass_id' => '-'], '10.0.0.9');

        $this->assertCount(2, $logger->records);
    }

    /**
     * @return AbstractLogger&object{records: list<array{string, string, array<string, mixed>}>}
     */
    private static function recordingLogger(): AbstractLogger
    {
        return new class() extends AbstractLogger {
            /** @var list<array{string, string, array<string, mixed>}> */
            public array $records = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->records[] = [(string) $level, (string) $message, $context];
            }
        };
    }
}
