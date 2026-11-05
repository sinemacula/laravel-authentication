<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonImmutable;
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
 * contract for a requirement the stored proofs cannot express, and reads the
 * session as committed when asked (`$current`), as the package asks wherever it
 * judges a session under its lock. An implementation must keep no state between
 * calls.
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
     * application.
     *
     * Asked plainly, that read takes no lock, and a transaction may serve it
     * from a snapshot taken before the caller's lock (MySQL's REPEATABLE READ):
     * a proof voided since may still count, and a revocation is not held off.
     * So a caller that acts on the answer atomically never acts on a plain one:
     * it asks with `$current` inside its transaction, on the session model's
     * connection. The session is then judged as committed: its row is read with
     * a lock held until the transaction ends and judged as above (a caller that
     * judges the row for more of its own locks it first: then one more
     * statement and no new lock), and its proofs are read current, so a proof
     * voided before the call never counts and one recorded before it does,
     * whatever the transaction read first. Lock order: the session's row, then
     * its proofs; take any other session's row before. The package asks so for
     * every freshness judgement it makes under a session's lock (a factor
     * change's gate, an identifier change request's check under the identity's
     * lock, a password establishment), so an implementation honours `$current`
     * (one that decorates the package's passes it on; one of its own locks the
     * session's row, judges it as above and reads its proofs as committed).
     * Asked current outside a transaction on that connection, the package's
     * implementation throws a `LogicException` before anything is read.
     *
     * With a factor excluded (the factor package's reference to it), a proof
     * made with that factor never meets the requirement: a factor's removal
     * must be authorised by the session's other proofs.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \LogicException
     */
    public function freshProof(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?RecordedProof;

    /**
     * Until when the session stays fresh for the operation: the second the
     * proof `freshProof()` answers stops meeting the effective requirement (its
     * time plus the requirement's maximum age; from that second on it is no
     * longer fresh), or `null` when `freshProof()` is `null`, read as
     * `freshProof()` reads it: plainly, or with `$current` on the session as
     * committed, for a caller that acts on it atomically. A grant that outlives
     * the request takes its expiry from it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    public function freshUntil(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?CarbonImmutable;
}
