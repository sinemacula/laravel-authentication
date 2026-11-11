<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Proves that a named principal belongs to an identity and returns the
 * resolver's own instance of it.
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
     * Resolve the named principal through the resolver, or `null` unless the
     * identity owns a principal of the same class and identifier.
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
     * Whether the principal's stored owner is the given identity.
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
