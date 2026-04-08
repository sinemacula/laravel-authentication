<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use Illuminate\Auth\Authenticatable as IlluminateAuthenticatable;

/**
 * Stateless re-export of Laravel's Authenticatable trait.
 *
 * Inert remember-token surface: the package is stateless-only and
 * never issues remember-me cookies (NFR-08), so the three remember
 * accessors are overridden to safe no-ops. Returning an empty
 * remember-token name from the inherited trait was historically
 * sufficient, but `EloquentUserProvider::retrieveByToken` would
 * still attempt to compose a query against the literal `""` column
 * if any consumer ever pointed it at a model using this trait. The
 * explicit no-ops below remove that footgun.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
     * Stateless package: remember tokens are never issued, so the
     * accessor returns `null` (the column does not exist).
     *
     * @return string|null
     */
    public function getRememberToken(): ?string
    {
        return null;
    }

    /**
     * Stateless package: remember tokens are never persisted, so
     * the setter is an explicit no-op. The parameter is accepted for
     * Laravel `Authenticatable` contract conformance and immediately
     * discarded.
     *
     * @param  mixed  $value
     * @return void
     */
    public function setRememberToken(#[\SensitiveParameter] mixed $value): void
    {
        unset($value); // contract-conformance no-op
    }
}
