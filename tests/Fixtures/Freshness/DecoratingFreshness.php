<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Freshness;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Freshness policy an adapter might bind over the package's: it delegates every
 * question to `ConfiguredFreshness`, the read mode included, and notes what it
 * was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecoratingFreshness implements FreshnessPolicy
{
    /** @var list<string> What the policy was asked, in order, by method name, followed by ` (current)` for a current judgement. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness  $inner
     */
    public function __construct(

        /** The package's policy every question is delegated to. */
        private readonly ConfiguredFreshness $inner,
    ) {}

    /**
     * The package's requirement.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     */
    #[\Override]
    public function requirement(string $application, string $operation, ?FreshnessRequirement $requirement = null): ?FreshnessRequirement
    {
        $this->asked[] = 'requirement';

        return $this->inner->requirement($application, $operation, $requirement);
    }

    /**
     * The package's answer, read as asked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    #[\Override]
    public function freshProof(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?RecordedProof {
        $this->asked[] = $current ? 'freshProof (current)' : 'freshProof';

        return $this->inner->freshProof($session, $operation, $requirement, $excludingFactor, $current);
    }

    /**
     * The package's answer, read as asked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?CarbonImmutable {
        $this->asked[] = $current ? 'freshUntil (current)' : 'freshUntil';

        return $this->inner->freshUntil($session, $operation, $requirement, $excludingFactor, $current);
    }
}
