<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Auth\Authenticatable as IlluminateAuthenticatable;

/**
 * Laravel's `Authenticatable` with the remember-token accessors made inert, as
 * the package is stateless.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait Authenticatable
{
    use IlluminateAuthenticatable;

    /**
     * Return an empty name, as there is no remember-token column.
     *
     * @return string
     */
    public function getRememberTokenName(): string
    {
        return '';
    }

    /**
     * Return an empty string, as there is no remember token.
     *
     * @return string
     *
     * @SuppressWarnings("php:S4144")
     */
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Ignore the value, as there is no remember token.
     *
     * @param  mixed  $value
     * @return void
     */
    public function setRememberToken(#[\SensitiveParameter] mixed $value): void
    {
        unset($value);
    }
}
