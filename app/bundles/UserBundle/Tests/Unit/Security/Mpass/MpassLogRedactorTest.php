<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Unit\Security\Mpass;

use Mautic\UserBundle\Security\Mpass\MpassLogRedactor;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;

final class MpassLogRedactorTest extends TestCase
{
    public function testSecretHeadersAreRedactedInEverySpellingAndDepth(): void
    {
        $record = new LogRecord(new \DateTimeImmutable(), 'mautic', Level::Warning, 'request', [
            'headers' => [
                'x-mpass-edge-secret'         => ['edge-value'],
                'X-Auth-Request-Access-Token' => ['token-value'],
                'x-auth-request-user'         => ['mpass-7'],
            ],
            'server' => ['HTTP_X_MPASS_EDGE_SECRET' => 'edge-value', 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'token-value', 'REMOTE_ADDR' => '10.0.0.9'],
            'path'   => '/s/account',
        ], ['X_MPASS_EDGE_SECRET' => 'edge-value']);

        $redacted = (new MpassLogRedactor())($record);

        $this->assertSame([
            'headers' => [
                'x-mpass-edge-secret'         => MpassLogRedactor::REDACTED,
                'X-Auth-Request-Access-Token' => MpassLogRedactor::REDACTED,
                'x-auth-request-user'         => ['mpass-7'],
            ],
            'server' => ['HTTP_X_MPASS_EDGE_SECRET' => MpassLogRedactor::REDACTED, 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => MpassLogRedactor::REDACTED, 'REMOTE_ADDR' => '10.0.0.9'],
            'path'   => '/s/account',
        ], $redacted->context);
        $this->assertSame(['X_MPASS_EDGE_SECRET' => MpassLogRedactor::REDACTED], $redacted->extra);
        $this->assertStringNotContainsString('-value', (string) json_encode([$redacted->context, $redacted->extra]));
    }
}
