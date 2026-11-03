<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Freshness;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Freshness policy an application might bind in place of the package's: it
 * answers the requirement it was given for every operation, finds a proof for
 * every session it is asked about (or none), whatever the session's proofs and
 * state, and notes what it was asked, so a test sees that the package asks the
 * bound policy and still judges the session itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedFreshness implements FreshnessPolicy
{
    /** @var list<string> What the policy was asked, in order: `requirement:<application>:<operation>`, `freshProof:<operation>[:<excluded factor>]` or `freshUntil:<operation>`. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  bool  $fresh
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Contracts\Session): void  $whenAsked
     */
    public function __construct(

        /** The requirement answered for every operation. */
        private readonly ?FreshnessRequirement $requirement,

        /** Whether every session it is asked about has a fresh proof. */
        private readonly bool $fresh = true,

        /** Run with the session each time a fresh proof is asked for. */
        private readonly ?\Closure $whenAsked = null,
    ) {}

    /**
     * The requirement it was given.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     */
    #[\Override]
    public function requirement(string $application, string $operation, ?FreshnessRequirement $requirement = null): ?FreshnessRequirement
    {
        $this->asked[] = "requirement:{$application}:{$operation}";

        return $this->requirement;
    }

    /**
     * A proof made now, or none, whatever the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    #[\Override]
    public function freshProof(Session $session, string $operation, ?FreshnessRequirement $requirement = null, ?string $excludingFactor = null): ?RecordedProof
    {
        $this->asked[] = $excludingFactor === null ? "freshProof:{$operation}" : "freshProof:{$operation}:{$excludingFactor}";

        if ($this->whenAsked !== null) {
            ($this->whenAsked)($session);
        }

        if (!$this->fresh) {
            return null;
        }

        return new RecordedProof(
            'proof-1',
            ProofKind::FIRST_FACTOR_REAUTHENTICATION,
            Purpose::REAUTHENTICATE,
            'password',
            new Channel(ChannelKind::PASSWORD),
            null,
            new ObservedProperties,
            null,
            ['pwd'],
            CarbonImmutable::now()->startOfSecond(),
        );
    }

    /**
     * A minute from now, or never, whatever the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(Session $session, string $operation, ?FreshnessRequirement $requirement = null, ?string $excludingFactor = null): ?CarbonImmutable
    {
        $this->asked[] = "freshUntil:{$operation}";

        return $this->fresh ? CarbonImmutable::now()->startOfSecond()->addMinute() : null;
    }
}
