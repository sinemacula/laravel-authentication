<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * Identity capability contract: owns principals.
 *
 * Implementations expose a `principals()` Eloquent relation builder
 * and a `resolveDefaultPrincipal()` method that returns the
 * application-defined default principal for 3D mode.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
     * Application-defined default principal lookup.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveDefaultPrincipal(): ?Principal;
}
