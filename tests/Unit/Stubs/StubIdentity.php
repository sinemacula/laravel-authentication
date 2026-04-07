<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Eloquent stub implementing Identity, HasPrincipals, and HasDevices.
 *
 * Used by guard and integration tests that need a real Eloquent
 * identity rather than a Mockery mock. Intentionally not `final` so
 * individual tests may extend it for hint-based or relation-based
 * scenarios (Mockery cannot subclass or partial-mock a final class).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
class StubIdentity extends Model implements HasDevices, HasPrincipals, Identity
{
    use Authenticatable;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Principal|null Test hook: principal returned by `resolveDefaultPrincipal()`. */
    public ?Principal $defaultPrincipal = null;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's principals.
     *
     * Tests typically override this via a Mockery partial. The default
     * returns a query builder against this model so PHPStan and Eloquent
     * remain happy without a database connection.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function principals(): Builder
    {
        return $this->newQuery();
    }

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function devices(): Builder
    {
        return $this->newQuery();
    }

    /**
     * Application-defined default principal lookup.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveDefaultPrincipal(): ?Principal
    {
        return $this->defaultPrincipal;
    }
}
