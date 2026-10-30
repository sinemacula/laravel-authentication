<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Scopes;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;

/**
 * Scope registry that may not grant `admin` to anyone, as an authorization
 * package's would for a scope no principal holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdminRejectingScopeRegistry implements ScopeRegistry
{
    /**
     * Reject `admin`.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  list<string>  $scopes
     * @return list<string>
     */
    #[\Override]
    public function rejected(string $guard, Principal $principal, array $scopes): array
    {
        unset($guard, $principal);

        return array_values(array_intersect($scopes, ['admin']));
    }
}
