<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * An identity that owns principals.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasPrincipals
{
    /**
     * Eloquent relation builder for the identity's principals.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function principals(): Builder;

    /**
     * The application's default principal for the identity.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveDefaultPrincipal(): ?Principal;
}
