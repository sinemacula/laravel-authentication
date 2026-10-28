<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Principal resolver whose hinted lookup is not scoped to the identity and that
 * sets the inverse `identity` relation on what it finds, so the membership it
 * returns claims the identity as its owner whatever its stored key says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InverseRelationMembershipResolver implements PrincipalResolver
{
    /**
     * Find the hinted membership by key alone and set the identity as its owner
     * relation, or return the identity's default principal when no hint is
     * given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        if ($hint !== null) {

            $membership = ActivatableTenantMembership::query()->with('tenant')->find($hint);

            return $membership instanceof ActivatableTenantMembership ? $membership->setRelation('identity', $identity) : null;
        }

        return $identity instanceof HasPrincipals ? $identity->resolveDefaultPrincipal() : null;
    }
}
