<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;

/**
 * Factor code counters contract.
 *
 * The factor package's per-factor and per-identity counts and lockouts for the
 * codes `CodeService::sendFactorCode()` sends and `verifyFactorCode()` checks:
 * the `mfa` challenges of a sign-in or a step-up, and the `enrollment`
 * challenges that confirm a factor being enrolled. This package keeps the
 * per-challenge counts (attempts, deliveries, the cooldown) and the per-IP
 * limits (`rate_limits.factor_code`, `rate_limits.code_request`); the
 * per-factor and per-identity ones are this contract's.
 *
 * The package's default, `RefuseFactorCodes`, refuses every code, so none is
 * sent or checked until a factor package binds a counter of its own. Fail
 * closed.
 *
 * `admit()` is asked before each delivery and each check, and `report()` once
 * for each attempt a check counts, with whether the code matched. Both are
 * asked inside the package's transaction on the storage connection (a savepoint
 * of the caller's, when it opened one), before the challenge's row is locked or
 * written, so the factor package takes its own locks first (the identity's
 * state, then its factors, then the challenge, then the session). Their writes
 * and locks must be on that same connection, so the attempt and its count
 * commit, or roll back, as one. An exception either throws propagates and rolls
 * the whole send or check back; never catch it to commit. `report()`'s answer
 * is authoritative: a matching code is verified only when it answers
 * `admitted`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorCodeCounters
{
    /**
     * Whether a code for the binding may be sent or checked now: the factor is
     * usable and neither it nor the identity is locked.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission;

    /**
     * Count one attempt at the challenge's code, which matched (`$passed`) or
     * did not, and answer whether its outcome stands: `admitted`, or a lock or
     * a refusal it caused or found.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission;
}
