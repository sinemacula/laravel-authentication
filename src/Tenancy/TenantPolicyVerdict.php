<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;

/**
 * A session judged against its tenant's authentication policy: how it stands,
 * and the version of the answer it was judged by (`null` for none, and for a
 * destination of no tenant, which has no policy).
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
     */
    public function __construct(

        /** How the session stands. */
        public TenantPolicyStanding $standing,

        /** The version of the answer, if it gave one. */
        public ?string $version,
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
