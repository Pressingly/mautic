<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * An asserted mPass identity that must not be admitted. Thrown from authenticate() before a
 * passport exists, so login_throttling never counts it.
 */
final class MpassRefusalException extends AuthenticationException
{
    public const UNRESOLVABLE  = 'unresolvable';
    public const CORPORATE     = 'corporate';
    public const INACTIVE      = 'inactive';
    public const ROLE          = 'role';
    public const CONFLICT      = 'conflict';

    public function __construct(public readonly string $reason, ?\Throwable $previous = null)
    {
        parent::__construct('mPass identity refused: '.$reason, 0, $previous);
    }

    public function getMessageKey(): string
    {
        return 'mautic.user.mpass.refused.'.$this->reason;
    }
}
