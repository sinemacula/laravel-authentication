<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding;

/**
 * The factor package's answer for a factor code, as `FactorCodeCounters` gives
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorCodeAdmission
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding  $standing
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     */
    private function __construct(

        /** Whether the code is admitted, locked or refused. */
        public FactorCodeStanding $standing,

        /** Until when the lock lasts, when the factor package says, for `locked` only. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Why the factor package refuses, for `refused` only. */
        public ?FactorCodeRefusal $refusal = null,
    ) {}

    /**
     * The code may be sent or checked, or the attempt's outcome stands.
     *
     * @return self
     */
    public static function admitted(): self
    {
        return new self(FactorCodeStanding::ADMITTED);
    }

    /**
     * The factor or the identity is locked, until the time given when there is
     * one.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return self
     */
    public static function locked(?CarbonImmutable $until = null): self
    {
        return new self(FactorCodeStanding::LOCKED, lockedUntil: $until);
    }

    /**
     * The factor package refuses, for the reason given.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return self
     */
    public static function refused(FactorCodeRefusal $refusal): self
    {
        return new self(FactorCodeStanding::REFUSED, refusal: $refusal);
    }

    /**
     * Whether the code is admitted.
     *
     * @return bool
     */
    public function isAdmitted(): bool
    {
        return $this->standing === FactorCodeStanding::ADMITTED;
    }
}
