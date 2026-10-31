<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Proves that a principal someone else named (one pinned on `attempt()` or on a
 * sign-in, or recorded on a pending sign-in) belongs to an identity, and
 * returns the resolver's own instance of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PinnedPrincipal
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Resolve the named principal through the resolver's hinted path, with the
     * exact-match check the bearer path applies to a `pid` claim, and return
     * the resolver's instance. Returns `null` when the identity does not own a
     * principal of the same class with that identifier.
     *
     * Ownership is checked here as well, rather than trusted to the resolver:
     * the resolved principal's own identity must be the given one, so a
     * resolver whose hinted lookup is not scoped to the identity cannot bind
     * another identity's principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public static function resolve(PrincipalResolver $resolver, Identity $identity, Principal $pinned): ?Principal
    {
        $hint     = $pinned->getPrincipalIdentifier();
        $resolved = $hint === null ? $resolver->resolve($identity) : $resolver->resolve($identity, $hint);

        if ($resolved === null || $resolved::class !== $pinned::class || !IdentifierCoercion::matches($resolved->getPrincipalIdentifier(), $hint)) {
            return null;
        }

        return self::isOwnedBy($resolved, $identity) ? $resolved : null;
    }

    /**
     * Whether the principal's owning identity is the given identity: the same
     * class with the same auth identifier. In 2D mode the principal is its own
     * identity.
     *
     * An Eloquent principal's owner is read from its own stored key through
     * `WriteConnection::stored()`, so an identity relation the resolver already
     * set (for example the inverse of the lookup it made) cannot vouch for the
     * principal. A principal whose owner cannot be read (`getIdentity()` throws
     * a `LogicException`, as `ActsAsPrincipal` does for a deleted owner or a
     * model without an identity relation) is not owned.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isOwnedBy(Principal $principal, Identity $identity): bool
    {
        try {
            $owner = WriteConnection::stored($principal, static fn (Principal $stored): Identity => $stored->getIdentity());
        } catch (\LogicException) {
            return false;
        }

        return $owner::class === $identity::class
            && IdentifierCoercion::matches($owner->getAuthIdentifier(), $identity->getAuthIdentifier());
    }
}
