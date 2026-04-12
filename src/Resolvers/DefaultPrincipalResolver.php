<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;

/**
 * Default principal resolver.
 *
 * Handles both 2D (identity-is-principal) and 3D (HasPrincipals delegate)
 * modes. Consumers may bind a custom resolver in the container for per-guard or
 * tenant-aware logic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class DefaultPrincipalResolver implements PrincipalResolver
{
    /**
     * Resolve a principal for the given identity.
     *
     * Resolution order:
     *  1. Hint + `ResolvesHintedPrincipal`: lookup via `resolveHintedPrincipal()`.
     *  2. Hint + `HasPrincipals`: lookup via `principals()->find()`.
     *  3. 2D: identity is itself a `Principal`.
     *  4. 3D: delegate to `resolveDefaultPrincipal()`.
     *  5. Otherwise throw `UnresolvableIdentityException`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed|null  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        if ($hint !== null && $identity instanceof ResolvesHintedPrincipal) {

            $hinted = $identity->resolveHintedPrincipal($hint);

            if ($hinted instanceof Principal) {
                return $hinted;
            }
        }

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

        throw new UnresolvableIdentityException(sprintf('Cannot resolve a principal for identity %s: it implements neither Principal nor HasPrincipals.', $identity::class));
    }
}
