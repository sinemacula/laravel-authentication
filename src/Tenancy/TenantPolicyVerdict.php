<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;

/**
 * A session judged against its tenant's authentication policy: how it stands,
 * the version of the answer it was judged by (`null` for none, and for a
 * destination of no tenant, which has no policy), when it falls short of a
 * further factor, the requirement it falls short of (empty otherwise), which a
 * pending session names as outstanding, and the first factor a further factor
 * was judged on, when the answer asked for one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantPolicyVerdict
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding  $standing
     * @param  ?string  $version
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     */
    public function __construct(

        /** How the session stands. */
        public TenantPolicyStanding $standing,

        /** The version of the answer, if it gave one. */
        public ?string $version,

        /** The further factor the session falls short of, empty unless it is `factor_required`. */
        public Requirement $factor = new Requirement,

        /** The first factor a further factor was judged on, `null` when the answer asked for none. */
        public ?RecordedProof $firstFactor = null,
    ) {}

    /**
     * Whether the session meets the policy.
     *
     * @return bool
     */
    public function isMet(): bool
    {
        return $this->standing === TenantPolicyStanding::MET;
    }
}
