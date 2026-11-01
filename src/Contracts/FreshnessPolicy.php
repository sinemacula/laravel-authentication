<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Freshness policy contract: whether a session's authentication is fresh enough
 * for an operation, judged on the newest proof that meets the operation's
 * requirement, never on the latest authentication time.
 *
 * An operation is named by this package (`Freshness\Operations`), the
 * application or another package (`mfa.add_factor`, `sso.reauthenticate`); a
 * caller may add a requirement of its own, and the stricter of it and the
 * configured one applies. An operation with neither is never fresh. The package
 * binds `Freshness\ConfiguredFreshness`, which reads the configured
 * requirements per application; an application or an adapter rebinds the
 * contract for a requirement the stored proofs cannot express. An
 * implementation must keep no state between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FreshnessPolicy
{
    /**
     * The requirement the operation must meet on the application: the stricter
     * of the configured one and the caller's, either alone when the other is
     * absent, and `null` (never fresh) with neither, or when the two have no
     * proof kind in common.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     */
    public function requirement(string $application, string $operation, ?FreshnessRequirement $requirement = null): ?FreshnessRequirement;

    /**
     * The newest of the session's proofs that meets that requirement now, or
     * `null` when none does. The session is read again by its key on the write
     * connection and must still record the same generation and owner (be the
     * session given, not another put under its key) and be live for its own
     * application. That read takes no lock, and a transaction may serve it from
     * a snapshot taken before the caller's lock (MySQL's REPEATABLE READ), so a
     * caller that acts on the answer atomically locks the session first and
     * judges the locked row itself as well.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    public function freshProof(Session $session, string $operation, ?FreshnessRequirement $requirement = null): ?RecordedProof;
}
