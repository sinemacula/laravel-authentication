<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;

/**
 * How a request for a one-time code ended: sent, with when the code expires;
 * rate limited, with the seconds until another may be requested; or refused
 * because the guard does not allow the method or the identifier is not one.
 *
 * A sign-in code is sent whether or not any identity has the identifier, so the
 * result is the same for an identifier no one has: answer it the same way.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeRequest
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus  $status
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** How the request ended. */
        public CodeRequestStatus $status,

        /** When the code sent stops working, for `sent` only. */
        public ?CarbonImmutable $expiresAt = null,

        /** Seconds until another code may be requested, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * A code was issued and its delivery queued.
     *
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return self
     */
    public static function sent(CarbonImmutable $expiresAt): self
    {
        return new self(CodeRequestStatus::SENT, expiresAt: $expiresAt);
    }

    /**
     * No code may be requested for the identifier, or from the IP address, for
     * the seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function rateLimited(int $retryAfter): self
    {
        return new self(CodeRequestStatus::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * The guard does not allow the code sign-in method.
     *
     * @return self
     */
    public static function methodNotAllowed(): self
    {
        return new self(CodeRequestStatus::METHOD_NOT_ALLOWED);
    }

    /**
     * The identifier is not one the type's normaliser accepts, or the identity
     * has no identifier of the type to verify.
     *
     * @return self
     */
    public static function identifierInvalid(): self
    {
        return new self(CodeRequestStatus::IDENTIFIER_INVALID);
    }

    /**
     * Whether a code was sent.
     *
     * @return bool
     */
    public function isSent(): bool
    {
        return $this->status === CodeRequestStatus::SENT;
    }
}
