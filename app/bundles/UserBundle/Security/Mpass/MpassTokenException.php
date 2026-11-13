<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

/**
 * Why a forwarded mPass token was not accepted. The reason is a short code for logs, never the token.
 */
final class MpassTokenException extends \RuntimeException
{
    public const MISSING               = 'missing_token';
    public const MALFORMED             = 'malformed';
    public const UNSUPPORTED_ALGORITHM = 'unsupported_algorithm';
    public const UNTRUSTED_ISSUER      = 'untrusted_issuer';
    public const UNKNOWN_SIGNING_KEY   = 'unknown_signing_key';
    public const BAD_SIGNATURE         = 'bad_signature';
    public const EXPIRED               = 'expired';
    public const NOT_YET_VALID         = 'not_yet_valid';
    public const MISSING_CLAIM         = 'missing_claim';
    public const WRONG_AUDIENCE        = 'wrong_audience';
    public const INVALID               = 'invalid';
    public const JWKS_UNAVAILABLE      = 'jwks_unavailable';
    public const VERIFIER_UNCONFIGURED = 'verifier_unconfigured';

    public function __construct(public readonly string $reason, ?\Throwable $previous = null)
    {
        parent::__construct('mPass token rejected: '.$reason, 0, $previous);
    }
}
