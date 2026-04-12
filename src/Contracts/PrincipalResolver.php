<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Principal resolver contract.
 *
 * Resolves a principal for an identity, optionally with a hint (e.g. a
 * principal id from a JWT payload). The default implementation covers both 2D
 * and 3D modes; consumers may bind a custom resolver in the container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PrincipalResolver
{
    /**
     * Resolve a principal for the given identity. The optional `$hint`
     * (typically a principal id from a token payload) lets resolvers
     * short-circuit the default lookup.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed|null  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolve(Identity $identity, mixed $hint = null): ?Principal;
}
