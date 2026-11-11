<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;

/**
 * The session service's factor-change gate, which `FactorChangeGate` carries
 * out.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait GatesFactorChanges
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\FactorChangeGate Judges a factor change from a session, on the guard's context. */
    private readonly FactorChangeGate $factorChanges;

    /**
     * Whether the factor package may make the change to the identity's further
     * factors from the session, asked inside the transaction that makes it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $factor
     * @return \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function factorChange(Session $session, FactorChange $change, ?FreshnessRequirement $requirement = null, ?string $factor = null): FactorChangeVerdict
    {
        return $this->factorChanges->verdict($session, $change, $requirement, $factor);
    }
}
