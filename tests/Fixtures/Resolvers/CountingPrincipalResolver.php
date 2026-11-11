<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Principal resolver that resolves an identity that is its own principal to
 * itself and counts how often it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingPrincipalResolver implements PrincipalResolver
{
    /** @var int How many times the resolver was asked for a principal. */
    public int $calls = 0;

    /**
     * The identity, when it is its own principal, counting the call.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($hint);

        $this->calls++;

        return $identity instanceof Principal ? $identity : null;
    }
}
