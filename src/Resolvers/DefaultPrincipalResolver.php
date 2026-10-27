<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * Default principal resolver.
 *
 * Handles both 2D (identity-is-principal) and 3D (HasPrincipals delegate)
 * modes. Consumers may bind a custom resolver in the container for per-guard or
 * tenant-aware logic.
 *
 * Principal lookups decide authentication, so every read goes to the write
 * connection: the `principals()->find()` query, and the identity's own
 * `resolveHintedPrincipal()` / `resolveDefaultPrincipal()` hooks, each run
 * inside `WriteConnection::during()` for the identity, which also covers the
 * relations a principal eager-loads, on any connection. A custom resolver
 * carries the same obligation (see `WriteConnection`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DefaultPrincipalResolver implements PrincipalResolver
{
    /**
     * Resolve a principal for the given identity.
     *
     * Resolution order:
     *  1. Hint + `ResolvesHintedPrincipal`: lookup via
     *  `resolveHintedPrincipal()`.
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
        if ($hint !== null) {

            $hinted = $this->resolveHinted($identity, $hint);

            if ($hinted !== null) {
                return $hinted;
            }
        }

        if ($identity instanceof Principal) {
            return $identity;
        }

        if ($identity instanceof HasPrincipals) {
            return WriteConnection::during($identity, static fn (): ?Principal => $identity->resolveDefaultPrincipal());
        }

        throw new UnresolvableIdentityException(sprintf('Cannot resolve a principal for identity %s: it implements neither Principal nor HasPrincipals.', $identity::class));
    }

    /**
     * Attempt hint-based principal resolution.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function resolveHinted(Identity $identity, mixed $hint): ?Principal
    {
        if ($identity instanceof ResolvesHintedPrincipal) {

            $hinted = WriteConnection::during($identity, static fn (): ?Principal => $identity->resolveHintedPrincipal($hint));

            if ($hinted instanceof Principal) {
                return $hinted;
            }
        }

        if ($identity instanceof HasPrincipals) {

            // Pinned for the whole lookup, not only its query: relations the
            // principal eager-loads (its tenant, say) run as separate queries.
            $hinted = WriteConnection::during($identity, static fn (): mixed => WriteConnection::query($identity->principals())->find($hint));

            if ($hinted instanceof Principal) {
                return $hinted;
            }
        }

        return null;
    }
}
