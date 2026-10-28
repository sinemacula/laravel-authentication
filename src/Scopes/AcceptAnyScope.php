<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Scopes;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;

/**
 * The package's default scope registry: every well-formed scope may be granted.
 * Bind another `ScopeRegistry` to hold credentials to the scopes that name real
 * permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AcceptAnyScope implements ScopeRegistry
{
    /**
     * Reject none of the scopes.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  list<string>  $scopes
     * @return list<string>
     */
    #[\Override]
    public function rejected(string $guard, Principal $principal, array $scopes): array
    {
        return [];
    }
}
