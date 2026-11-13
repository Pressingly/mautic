<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Monolog\LogRecord;

/**
 * Masks the edge secret and the forwarded mPass token wherever a log record carries headers, in
 * either spelling (X-Mpass-Edge-Secret or HTTP_X_MPASS_EDGE_SECRET), at any depth of the context.
 */
final class MpassLogRedactor
{
    public const REDACTED = '[redacted]';

    private const SECRET_HEADERS = ['x-mpass-edge-secret', 'x-auth-request-access-token'];

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(context: self::redact($record->context), extra: self::redact($record->extra));
    }

    /**
     * @param array<mixed> $values
     *
     * @return array<mixed>
     */
    public static function redact(array $values): array
    {
        $redacted = [];
        foreach ($values as $key => $value) {
            $redacted[$key] = match (true) {
                self::isSecretHeader((string) $key) => self::REDACTED,
                is_array($value)                    => self::redact($value),
                default                             => $value,
            };
        }

        return $redacted;
    }

    private static function isSecretHeader(string $key): bool
    {
        $name = strtolower(str_replace('_', '-', preg_replace('/^HTTP_/i', '', $key) ?? $key));

        return in_array($name, self::SECRET_HEADERS, true);
    }
}
