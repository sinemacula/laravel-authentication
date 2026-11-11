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
 * The package's freshness policy: the configured requirement for each
 * operation, made stricter by the caller's.
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
     * The stricter of the configured requirement and the caller's, or `null`
     * when there is none to meet.
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
     * `null` when none does.
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
     * Until when the session stays fresh for the operation, or `null` when no
     * proof makes it fresh.
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
     * requirement, or `null` (see `freshProof()`).
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
     * connection, where it would not be atomic.
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
