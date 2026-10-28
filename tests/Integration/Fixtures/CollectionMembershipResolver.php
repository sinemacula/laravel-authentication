<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Principal resolver that loads every membership of the identity, with its
 * owner and tenant eager-loaded, and picks the hinted one from the collection,
 * so the membership it returns is one of several hydrated rows (which Eloquent
 * marks as preventing lazy loads under strict mode).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CollectionMembershipResolver implements PrincipalResolver
{
    /**
     * Pick the hinted membership from the identity's memberships, or return the
     * identity's default principal when no hint is given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        if ($hint !== null) {

            $membership = ActivatableTenantMembership::query()
                ->where('identity_id', $identity->getAuthIdentifier())
                ->with(['identity', 'tenant'])
                ->get()
                ->firstWhere('id', $hint);

            return $membership instanceof Principal ? $membership : null;
        }

        return $identity instanceof HasPrincipals ? $identity->resolveDefaultPrincipal() : null;
    }
}
