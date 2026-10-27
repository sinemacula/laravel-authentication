<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Principal resolver whose hinted lookup is not scoped to the identity: it
 * finds any membership by its key, the mistake the guard's own ownership check
 * on a pinned principal guards against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnscopedMembershipResolver implements PrincipalResolver
{
    /**
     * Find the hinted membership by key alone, or the identity's default
     * principal when no hint is given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        if ($hint !== null) {

            $membership = ActivatableTenantMembership::query()->find($hint);

            return $membership instanceof Principal ? $membership : null;
        }

        return $identity instanceof HasPrincipals ? $identity->resolveDefaultPrincipal() : null;
    }
}
