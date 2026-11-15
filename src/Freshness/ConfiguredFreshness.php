<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\HasGuardContext;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
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
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(

        /** Configuration the requirements are read from on every call. */
        private Repository $config,

        /** The auth manager a session's owner is reloaded through. */
        private AuthFactory $auth,
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
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshProof(Session $session, string $operation, ?FreshnessRequirement $requirement = null, bool $current = false): ?RecordedProof
    {
        if ($current) {
            self::refuseOutsideTransaction();
        }

        return $this->fresh($session, $operation, $requirement, $current)[0] ?? null;
    }

    /**
     * Until when the session stays fresh for the operation, or `null` when no
     * proof makes it fresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshUntil(Session $session, string $operation, ?FreshnessRequirement $requirement = null, bool $current = false): ?CarbonImmutable
    {
        if ($current) {
            self::refuseOutsideTransaction();
        }

        $fresh = $this->fresh($session, $operation, $requirement, $current);

        return $fresh === null ? null : $fresh[0]->authenticatedAt->addSeconds($fresh[1]->maxAgeSeconds);
    }

    /**
     * Until when the session stays both fresh for the operation and meeting the
     * requirement, judged apart, or `null` when it is not both now.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  bool  $current
     * @param  ?string  $excludingFactor
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function metUntil(Session $session, string $operation, Requirement $requirement, bool $current = false, ?string $excludingFactor = null): ?CarbonImmutable
    {
        self::assertAgeBounded($requirement);

        if ($current) {
            self::refuseOutsideTransaction();
        }

        $guard      = WriteConnection::during($session, static fn (): ?string => $session->getGuard());
        $configured = $guard === null ? null : $this->requirement($guard, $operation);

        if ($guard === null || !FreshnessSettings::isOperation($operation) || ($configured === null && $requirement->isEmpty())) {
            return null;
        }

        $stored = self::stored($session, $guard, $current);

        if ($stored === null) {
            return null;
        }

        [$row, $now] = $stored;
        $until       = $this->earliestDeadline($row, $guard, $configured, $requirement, $now, new ProofSource(current: $current, excludingFactor: $excludingFactor));

        return $until?->greaterThan($now) === true ? $until : null;
    }

    /**
     * The earlier of the configured requirement's deadline and the time the
     * requirement is met until, each given, or `null` when either has none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $configured
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function earliestDeadline(
        EloquentSession&Model $session,
        string $guard,
        ?FreshnessRequirement $configured,
        Requirement $requirement,
        CarbonImmutable $now,
        ProofSource $source,
    ): ?CarbonImmutable {
        $deadlines = [];

        if ($configured !== null) {
            $proof       = SessionProofs::newestMeeting($session, $configured, $now, $source->excludingFactor, $source->current);
            $deadlines[] = $proof?->authenticatedAt->addSeconds($configured->maxAgeSeconds);
        }

        if (!$requirement->isEmpty()) {
            $resolved    = $this->auth->guard($guard);
            $owner       = $resolved instanceof HasGuardContext ? SessionOwnership::reloadedOwner($session, $resolved->context()->provider()) : null;
            $deadlines[] = $owner === null ? null : RequirementJudge::metEvaluation($guard, $owner, $session, null, $now, $source, $requirement)?->metUntil;
        }

        /** @var non-empty-list<?\Carbon\CarbonImmutable> $deadlines */
        return in_array(null, $deadlines, true) ? null : min($deadlines);
    }

    /**
     * The newest proof that meets the effective requirement now, with that
     * requirement, or `null` (see `freshProof()`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  bool  $current
     * @return ?array{0: \SineMacula\Laravel\Authentication\Proofs\RecordedProof, 1: \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function fresh(Session $session, string $operation, ?FreshnessRequirement $requirement, bool $current): ?array
    {
        $guard     = WriteConnection::during($session, static fn (): ?string => $session->getGuard());
        $effective = $guard === null ? null : $this->requirement($guard, $operation, $requirement);
        $stored    = $guard === null || $effective === null ? null : self::stored($session, $guard, $current);

        if ($effective === null || $stored === null) {
            return null;
        }

        $proof = SessionProofs::newestMeeting($stored[0], $effective, $stored[1], current: $current);

        return $proof === null ? null : [$proof, $effective];
    }

    /**
     * The session's row, read again, and the time it is judged at, when the row
     * is still that session and live for its guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @param  bool  $current
     * @return ?array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \Carbon\CarbonImmutable}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private static function stored(Session $session, string $guard, bool $current): ?array
    {
        if (!$session instanceof EloquentSession || !$session instanceof Model) {
            return null;
        }

        $key    = $session->getSessionIdentifier();
        $stored = $current ? SessionLookup::lock($key) : SessionLookup::find($key);
        $now    = CarbonImmutable::now()->startOfSecond();

        return SessionOwnership::isSameSession($session, $stored) && OwnedSession::refusal($stored, $guard, $now) === null ? [$stored, $now] : null;
    }

    /**
     * Refuse a requirement with a part of any age or older than a day.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertAgeBounded(Requirement $requirement): void
    {
        foreach ([$requirement->additionalVerification, $requirement->multifactor, $requirement->minimumLevel, $requirement->phishingResistance] as $part) {
            if ($part !== null && ($part->maxAgeSeconds === null || $part->maxAgeSeconds > FreshnessRequirement::MAX_AGE_SECONDS)) {
                $message = sprintf('Each part of a requirement judged for freshness must give a maximum age from 1 to %d seconds.', FreshnessRequirement::MAX_AGE_SECONDS);

                throw new \InvalidArgumentException($message);
            }
        }
    }

    /**
     * Refuse a current judgement outside a transaction on the storage
     * connection, where it would not be atomic.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function refuseOutsideTransaction(): void
    {
        if (!StorageConnection::isInTransaction()) {
            throw new \LogicException('A current freshness judgement is asked inside a transaction on the session model\'s connection.');
        }
    }
}
