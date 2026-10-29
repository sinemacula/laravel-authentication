<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Principal resolver that loads the identity's typed memberships with only the
 * columns it needs to find them (`id`, `identity_id` and `tenant_id`), leaving
 * out the `type` column, as a lookup tuned for speed might.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ColumnSelectingMembershipResolver implements PrincipalResolver
{
    /**
     * Find the hinted membership among the identity's own, or its first one
     * when no hint is given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        $query = TypedMembership::query()
            ->select(['id', 'identity_id', 'tenant_id'])
            ->where('identity_id', $identity->getAuthIdentifier());

        $membership = $hint === null ? $query->orderBy('id')->first() : $query->find($hint);

        return $membership instanceof Principal ? $membership : null;
    }
}
