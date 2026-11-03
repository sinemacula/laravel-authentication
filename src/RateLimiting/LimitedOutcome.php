<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

/**
 * How a flow whose outcomes an enum of its own names ended (`outcome`), with
 * the seconds until it may be tried again once it was `rate_limited`: what a
 * check of a verification code (`VerificationOutcome`) and a confirmation of a
 * change of identifier (`IdentifierChangeOutcome`) answer, so a throttled one
 * can be answered with its `Retry-After`.
 *
 * @template-covariant TOutcome of \BackedEnum
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LimitedOutcome
{
    /**
     * Constructor.
     *
     * @param  TOutcome  $outcome
     * @param  ?int  $retryAfter
     */
    public function __construct(

        /** How the flow ended. */
        public \BackedEnum $outcome,

        /** Seconds until the flow may be tried again, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * Whether the flow ended as the outcome given.
     *
     * @param  \BackedEnum  $outcome
     * @return bool
     */
    public function is(\BackedEnum $outcome): bool
    {
        return $this->outcome === $outcome;
    }
}
