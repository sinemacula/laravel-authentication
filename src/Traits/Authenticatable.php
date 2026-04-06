<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Traits;

use Illuminate\Auth\Authenticatable as IlluminateAuthenticatable;

/**
 * Stateless re-export of Laravel's Authenticatable trait.
 *
 * The remember-token column name is zeroed out because this package
 * is stateless-only and never issues remember-me cookies (NFR-08).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
trait Authenticatable
{
    use IlluminateAuthenticatable;

    /** Stateless package: there is no remember-token column. */
    public function getRememberTokenName(): string
    {
        return '';
    }
}
