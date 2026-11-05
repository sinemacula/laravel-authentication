<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * The package's freshness policy: the requirement each operation has on each
 * application is the configured one (see `FreshnessSettings`), made stricter by
 * the caller's, and a session is fresh for it when its newest counting proof
 * the requirement takes was made within the requirement's age.
 *
 * The requirement is the one of the application the caller's session names, and
 * with none, nothing is read. Otherwise the session is never trusted as the
 * caller holds it, which may predate a revocation: it is read again by its key
 * on the write connection and must still be the caller's session, recording the
 * generation and the owner the caller's does (a session model that reissues
 * keys may have put another session under it, another identity's or a later one
 * of the same identity), and be live for that application (of that guard, not
 * revoked, not ended) before its proofs are read, two queries in all; a session
 * that is not an Eloquent session records neither, and is answered without a
 * query. Asked plainly, that read takes no lock, so a caller that acts on the
 * answer atomically asks current inside its transaction (`$current`), which
 * reads the session's row with a lock held until the transaction ends, judges
 * it as above, and reads its proofs current (see `SessionProofs`), still two
 * queries. A session stays fresh until its newest qualifying proof is as old as
 * the requirement's maximum age (`freshUntil()`, read either way).
 *
 * Stateless: the configuration is read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFreshness implements FreshnessPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the requirements are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The requirement the operation must meet on the application: the stricter
     * of the configured one and the caller's, either alone when the other is
     * absent, and `null` with neither, when they have no proof kind in common,
     * or for a name that is not an operation's.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function requirement(string $application, string $operation, ?FreshnessRequirement $requirement = null): ?FreshnessRequirement
    {
        if (!FreshnessSettings::isOperation($operation)) {
            return null;
        }

        $configured = (new FreshnessSettings($this->config))->requirement($application, $operation);

        return match (true) {
            $configured  === null => $requirement,
            $requirement === null => $configured,
            default               => $configured->stricter($requirement),
        };
    }

    /**
     * The newest of the session's proofs that meets the requirement now, or
     * `null` when the session names no application, there is no requirement,
     * the stored session is gone, records another generation or another owner
     * (or the session given is not an Eloquent session, which records neither)
     * or is no longer live for that application, or no proof meets it. A proof
     * made with the excluded factor, if one is named, never meets it.
     *
     * Asked current (`$current`), it is judged inside the caller's transaction
     * on the session model's connection on the session as committed: its row
     * read with a lock held until the transaction ends, its proofs read
     * current. Outside a transaction on that connection a `LogicException` is
     * thrown before anything is read: two statements outside one would make no
     * atomic judgement, and a plain read serves the caller that needs none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshProof(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?RecordedProof {
        if ($current) {
            self::refuseOutsideTransaction(SessionLookup::model()->getConnection());
        }

        return $this->fresh($session, $operation, $requirement, $excludingFactor, $current)[0] ?? null;
    }

    /**
     * Until when the session stays fresh for the operation: the time of the
     * proof `freshProof()` answers, read as asked (`$current` included, and
     * refused outside a transaction alike), plus the effective requirement's
     * maximum age, or `null` when there is no such proof.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshUntil(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?CarbonImmutable {
        if ($current) {
            self::refuseOutsideTransaction(SessionLookup::model()->getConnection());
        }

        $fresh = $this->fresh($session, $operation, $requirement, $excludingFactor, $current);

        return $fresh === null ? null : $fresh[0]->authenticatedAt->addSeconds($fresh[1]->maxAgeSeconds);
    }

    /**
     * The newest proof that meets the effective requirement now, with that
     * requirement, or `null` (see `freshProof()`); with `$current`, the
     * session's row is read locked and its proofs current.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?array{0: \SineMacula\Laravel\Authentication\Proofs\RecordedProof, 1: \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function fresh(Session $session, string $operation, ?FreshnessRequirement $requirement, ?string $excludingFactor, bool $current): ?array
    {
        $guard     = WriteConnection::during($session, static fn (): ?string => $session->getGuard());
        $effective = $guard === null ? null : $this->requirement($guard, $operation, $requirement);

        if ($guard === null || $effective === null || !$session instanceof EloquentSession || !$session instanceof Model) {
            return null;
        }

        $key    = $session->getSessionIdentifier();
        $stored = $current ? SessionLookup::lock($key) : SessionLookup::find($key);
        $now    = CarbonImmutable::now()->startOfSecond();

        $proof = !SessionOwnership::isSameSession($session, $stored) || OwnedSession::refusal($stored, $guard, $now) !== null
            ? null
            : SessionProofs::newestMeeting($stored, $effective, $now, $excludingFactor, $current);

        return $proof === null ? null : [$proof, $effective];
    }

    /**
     * Refuse a current judgement outside a transaction on the session model's
     * connection, before anything is read: outside one its two statements would
     * make no atomic judgement.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseOutsideTransaction(Connection $connection): void
    {
        if ($connection->transactionLevel() === 0) {
            throw new \LogicException('A current freshness judgement is asked inside a transaction on the session model\'s connection.');
        }
    }
}
