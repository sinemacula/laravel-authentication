<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Stub resolver that returns a default principal when no hint is supplied, or
 * looks up the hinted principal from a pre-built map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubMappedPrincipalResolver implements PrincipalResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $defaultPrincipal
     * @param  array<string, \SineMacula\Laravel\Authentication\Contracts\Principal>  $hintedPrincipals
     */
    public function __construct(

        /** The fallback principal when no hint is supplied. */
        private readonly Principal $defaultPrincipal,

        /** Map of principal id to principal instance. */
        private readonly array $hintedPrincipals,
    ) {}

    /**
     * Resolve the default principal when no hint is provided, otherwise return
     * the principal mapped to the hinted id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity);

        if (is_string($hint) || is_int($hint)) {
            return $this->hintedPrincipals[(string) $hint] ?? null;
        }

        return $this->defaultPrincipal;
    }
}
