<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Decides which scopes a credential may grant its principal when it is issued
 * or rotated.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ScopeRegistry
{
    /**
     * The scopes, of those given, that may not be granted to the principal on
     * the guard; `[]` accepts them all.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  list<string>  $scopes
     * @return list<string>
     */
    public function rejected(string $guard, Principal $principal, array $scopes): array;
}
