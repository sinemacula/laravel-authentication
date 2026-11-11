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
 * Default principal resolver, for identities that are their own principal or
 * delegate through `HasPrincipals`, reading on the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DefaultPrincipalResolver implements PrincipalResolver
{
    /**
     * Resolve a principal for the identity: by hint first, else the identity
     * itself, else its default principal.
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

            // Pinned for the whole lookup: eager loads run as separate queries
            $hinted = WriteConnection::during($identity, static fn (): mixed => WriteConnection::query($identity->principals())->find($hint));

            if ($hinted instanceof Principal) {
                return $hinted;
            }
        }

        return null;
    }
}
