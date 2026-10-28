<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Scope registry contract.
 *
 * Asked whenever a credential (an API key) is issued or rotated which of the
 * scopes it is to grant may not be granted to its principal on the guard. The
 * package carries scopes and never interprets them: a scope is an opaque
 * string, and a ceiling the application's authorization intersects with the
 * principal's permissions, never a permission itself. The package's default
 * accepts every well-formed scope; an authorization package or the application
 * binds its own registry so a credential can only carry scopes that name real
 * permissions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ScopeRegistry
{
    /**
     * The scopes, of those given, that may not be granted to the principal on
     * the guard; `[]` accepts them all. The scopes given are already
     * well-formed and free of duplicates.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  list<string>  $scopes
     * @return list<string>
     */
    public function rejected(string $guard, Principal $principal, array $scopes): array;
}
