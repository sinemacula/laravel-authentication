<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The factor-change gate's answer: allowed, until when, or refused, with why.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChangeVerdict
{
    /**
     * Constructor.
     *
     * @param  ?\Carbon\CarbonImmutable  $freshUntil
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The second the session stops being fresh for the change, when it is allowed. */
        public ?CarbonImmutable $freshUntil,

        /** Why the change is refused, when it is. */
        public ?FailureReason $reason,
    ) {}

    /**
     * An allowed change.
     *
     * @param  \Carbon\CarbonImmutable  $freshUntil
     * @return self
     */
    public static function allowed(CarbonImmutable $freshUntil): self
    {
        return new self($freshUntil, null);
    }

    /**
     * A refused change.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * Whether the change is allowed.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->reason === null;
    }
}
