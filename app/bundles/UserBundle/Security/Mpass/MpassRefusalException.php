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
    public const TOKEN         = 'token';

    public const NOT_CORPORATE      = 'not_corporate';
    public const WRONG_ORGANIZATION = 'wrong_organization';

    /**
     * @param string $detail a finer reason code for the log (e.g. an MpassTokenException reason), never shown
     */
    public function __construct(public readonly string $reason, ?\Throwable $previous = null, public readonly string $detail = '')
    {
        parent::__construct('mPass identity refused: '.$reason, 0, $previous);
    }

    /**
     * Only a verified token naming another tenant ends an established session. Every other
     * refusal, transient or not (missing, expired, bad signature, untrusted issuer, wrong audience,
     * JWKS down, verifier not configured), is logged and survived by an established session, and
     * refused for a new one.
     */
    public function endsEstablishedSession(): bool
    {
        return self::CORPORATE === $this->reason && in_array($this->detail, [self::NOT_CORPORATE, self::WRONG_ORGANIZATION], true);
    }

    public function getMessageKey(): string
    {
        return 'mautic.user.mpass.refused.'.$this->reason;
    }
}
