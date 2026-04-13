<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Mutable stub resolver whose default and hinted principals can be
 * swapped at test-time via setters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubMutablePrincipalResolver implements PrincipalResolver
{
    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Principal */
    private ?Principal $defaultPrincipal = null;

    /** @var array<string, \SineMacula\Laravel\Authentication\Contracts\Principal> */
    private array $hintedPrincipals = [];

    /**
     * Set the default principal returned when no hint is provided.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return void
     */
    public function setDefaultPrincipal(?Principal $principal): void
    {
        $this->defaultPrincipal = $principal;
    }

    /**
     * Set or replace a hinted-principal mapping.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return void
     */
    public function setHintedPrincipal(string $id, Principal $principal): void
    {
        $this->hintedPrincipals[$id] = $principal;
    }

    /**
     * Resolve the principal for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity);

        if (is_string($hint) && array_key_exists($hint, $this->hintedPrincipals)) {
            return $this->hintedPrincipals[$hint];
        }

        return $this->defaultPrincipal;
    }
}
