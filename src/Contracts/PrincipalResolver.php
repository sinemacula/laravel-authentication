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
 * The resolved principal decides authentication, so an implementation must read
 * it from the write connection, never a read replica that can lag behind a
 * deactivation or deletion (see `Database\WriteConnection`).
 *
 * A hint can come from a caller (a principal pinned on `attempt()`), not only
 * from a signed token, so an implementation must only ever return a principal
 * that belongs to the identity it is given: scope the hinted lookup to that
 * identity. The guard also checks a pinned principal's owner, but a resolver
 * must not rely on that.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PrincipalResolver
{
    /**
     * Resolve a principal for the given identity. The optional `$hint`
     * (typically a principal id from a token payload) lets resolvers
     * short-circuit the default lookup. The result, hinted or not, must belong
     * to `$identity`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed|null  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function resolve(Identity $identity, mixed $hint = null): ?Principal;
}
