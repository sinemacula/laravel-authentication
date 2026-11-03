<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;

/**
 * How a request for a one-time code ended: sent, with the challenge it was
 * delivered for and when the code expires; rate limited, or out of deliveries
 * for the destination's window, with the seconds until another may be
 * requested; refused because the guard does not allow the method or the
 * identifier is not one; or, for a factor code, locked or refused by the factor
 * package.
 *
 * A sign-in code, and a password reset link or code, is sent whether or not any
 * identity has the identifier, so the result is the same for an identifier no
 * one has: answer it the same way. A reset is refused as `method_not_allowed`
 * when the guard does not allow passwords. A code is checked with the challenge
 * id it was sent for, which a resend keeps; a reset link's token is its own
 * challenge and carries none.
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
     * @param  ?string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     */
    private function __construct(

        /** How the request ended. */
        public CodeRequestStatus $status,

        /** When the code sent stops working, for `sent` only. */
        public ?CarbonImmutable $expiresAt = null,

        /** Seconds until another code may be requested, for `rate_limited` and `deliveries_exhausted` only. */
        public ?int $retryAfter = null,

        /** The challenge the code was sent for, which its check names, for a code `sent` only. */
        public ?string $challengeId = null,

        /** Until when the factor package has the factor or the identity locked, for `locked` only, when it said. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Why the factor package refused, for `refused` only. */
        public ?FactorCodeRefusal $refusal = null,
    ) {}

    /**
     * A code was issued and its delivery queued, for the challenge given (none
     * for a reset link, whose token is its own).
     *
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?string  $challengeId
     * @return self
     */
    public static function sent(CarbonImmutable $expiresAt, ?string $challengeId = null): self
    {
        return new self(CodeRequestStatus::SENT, expiresAt: $expiresAt, challengeId: $challengeId);
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
     * The destination's delivery window has had all the deliveries it allows;
     * another may be requested in the seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function deliveriesExhausted(int $retryAfter): self
    {
        return new self(CodeRequestStatus::DELIVERIES_EXHAUSTED, retryAfter: $retryAfter);
    }

    /**
     * The factor package has the factor or the identity locked, until the time
     * given when it said.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return self
     */
    public static function locked(?CarbonImmutable $until): self
    {
        return new self(CodeRequestStatus::LOCKED, lockedUntil: $until);
    }

    /**
     * The factor package refuses to have the code sent, for the reason given.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return self
     */
    public static function refused(?FactorCodeRefusal $refusal): self
    {
        return new self(CodeRequestStatus::REFUSED, refusal: $refusal);
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
