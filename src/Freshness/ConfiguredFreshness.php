<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;

/**
 * The package's freshness policy: the requirement each operation has on each
 * application is the configured one (see `FreshnessSettings`), made stricter by
 * the caller's, and a session is fresh for it when its newest counting proof
 * the requirement takes was made within the requirement's age.
 *
 * The requirement is the one of the application the caller's session names, and
 * with none, nothing is read. Otherwise the session is never trusted as the
 * caller holds it, which may predate a revocation: it is read again by its key
 * on the write connection and must still be live for that application (of that
 * guard, not revoked, not ended) before its proofs are read, two queries in
 * all. That read takes no lock, so a caller that acts on the answer atomically
 * locks the session in its transaction first, judges the locked row itself, and
 * asks inside it.
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
     * the stored session is gone or no longer live for that application, or no
     * proof meets it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshProof(Session $session, string $operation, ?FreshnessRequirement $requirement = null): ?RecordedProof
    {
        $guard     = WriteConnection::during($session, static fn (): ?string => $session->getGuard());
        $effective = $guard === null ? null : $this->requirement($guard, $operation, $requirement);

        if ($guard === null || $effective === null) {
            return null;
        }

        $stored = SessionLookup::find($session->getSessionIdentifier());
        $now    = CarbonImmutable::now()->startOfSecond();

        return $stored === null || OwnedSession::refusal($stored, $guard, $now) !== null ? null : SessionProofs::newestMeeting($stored, $effective, $now);
    }
}
