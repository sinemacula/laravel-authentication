<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;

/**
 * How checking a further factor's code, or an enrolment's, ended
 * (`CodeService::verifyFactorCode()`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorCodeCheck
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $verifiedAt
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @param  ?int  $retryAfter
     */
    public function __construct(

        /** How the check ended. */
        public FactorCodeOutcome $outcome,

        /** The challenge id the check was made against, as given. */
        public string $challengeId,

        /** When the code was verified, for `verified` only. */
        public ?CarbonImmutable $verifiedAt = null,

        /** Until when the factor package has the factor or the identity locked, when it said. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Why the factor package refused, when it did. */
        public ?FactorCodeRefusal $refusal = null,

        /** Seconds until the IP address may check another code, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * Whether the code matched the live challenge and the factor package
     * admitted the outcome.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->outcome === FactorCodeOutcome::VERIFIED;
    }
}
