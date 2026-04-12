<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use Illuminate\Auth\Authenticatable as IlluminateAuthenticatable;

/**
 * Stateless re-export of Laravel's Authenticatable trait.
 *
 * Overrides the three remember-token accessors to inert no-ops because the
 * package is stateless-only. Without the explicit overrides
 * `EloquentUserProvider::retrieveByToken` would still attempt to query the
 * literal `""` column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait Authenticatable
{
    use IlluminateAuthenticatable;

    /**
     * Stateless package: there is no remember-token column.
     *
     * @return string
     */
    public function getRememberTokenName(): string
    {
        return '';
    }

    /**
     * Stateless package: returns `null`.
     *
     * @return ?string
     */
    public function getRememberToken(): ?string
    {
        return null;
    }

    /**
     * Stateless package: explicit no-op.
     *
     * @param  mixed  $value
     * @return void
     */
    public function setRememberToken(#[\SensitiveParameter] mixed $value): void
    {
        unset($value);
    }
}
