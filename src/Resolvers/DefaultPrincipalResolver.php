<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Resolvers;

use LogicException;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Default principal resolver.
 *
 * Handles both 2D (identity-is-principal) and 3D (HasPrincipals delegate)
 * modes in a single class. Consumers may bind a custom resolver in the
 * container if their domain needs per-guard or tenant-aware logic.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class DefaultPrincipalResolver implements PrincipalResolver
{
    /**
     * Resolve a principal for the given identity.
     *
     * Resolution order:
     *  1. Hint path: when a hint is supplied and the identity implements
     *     `HasPrincipals`, look up the hinted principal via
     *     `$identity->principals()->find($hint)`.
     *  2. 2D path: if the identity itself implements `Principal`, return it.
     *  3. 3D path: if the identity implements `HasPrincipals`, delegate to
     *     `$identity->resolveDefaultPrincipal()`.
     *  4. Otherwise throw a `\LogicException` naming the offending class.
     */
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        if ($hint !== null && $identity instanceof HasPrincipals) {

            $hinted = $identity->principals()->find($hint);

            if ($hinted instanceof Principal) {
                return $hinted;
            }
        }

        if ($identity instanceof Principal) {
            return $identity;
        }

        if ($identity instanceof HasPrincipals) {
            return $identity->resolveDefaultPrincipal();
        }

        throw new LogicException(sprintf(
            'Cannot resolve a principal for identity %s: it implements neither Principal nor HasPrincipals.',
            $identity::class,
        ));
    }
}
