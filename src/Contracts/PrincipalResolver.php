<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Principal resolver contract.
 *
 * Implementations resolve a principal for a given identity, optionally
 * accepting a hint such as a principal id from a JWT payload. The
 * package's default `DefaultPrincipalResolver` covers both 2D mode
 * (identity-is-principal) and 3D mode (`HasPrincipals` delegate);
 * consumers may bind a custom resolver in the container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface PrincipalResolver
{
    /**
     * Resolve a principal for the given identity.
     *
     * Implementations MUST NOT embed domain queries inside guards.
     * The optional `$hint` is an arbitrary value (typically a principal
     * id from a token payload) that the resolver may use to short-circuit
     * the default lookup.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed|null  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolve(Identity $identity, mixed $hint = null): ?Principal;
}
