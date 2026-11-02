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
 * A delegation with no state of its own; it sits in a trait only so the service
 * stays within the number of methods one class may declare.
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
     * factors from the session, asked inside the transaction that makes it, on
     * the storage connection, after the factor package's own locks.
     *
     * The session's row is locked until that transaction ends; it must still be
     * the session given, one of this guard's live, active sessions
     * (`session_unknown`, `session_guard_mismatch`, `session_revoked`,
     * `session_pending`, `session_expired`) and a person's
     * (`machine_identity`). A pending session's bootstrap enrolment is not a
     * change made here: it goes through the pending credential's actions
     * (`pending()` with `start_bootstrap_enrollment` or
     * `confirm_bootstrap_enrollment`), while enrolment is its first requirement
     * and until the credential expires. Then the session must be fresh for the
     * change: an identity's first additional factor (`ADD_FIRST`, which the
     * factor package names, knowing the identity has none) for
     * `first_additional_factor`, by default a reauthentication with the first
     * factor within 15 minutes (`reauthentication_required`); every other
     * change for `factor_change`, by default a step-up within 15 minutes
     * (`step_up_required`), the factor a replacement or removal names (required
     * for those, refused for the others with an `InvalidArgumentException`)
     * never counting for its own change. The caller may add a requirement of
     * its own; the stricter applies.
     *
     * An allowed verdict carries the fresh proof and the second the session
     * stops being fresh for the change, which a grant that outlives the request
     * takes its expiry from. The gate writes nothing and reports nothing.
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
