<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Eloquent identity with principals and sessions, left non-final so tests can
 * extend or partial-mock it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubIdentity extends Model implements HasPrincipals, HasSessions, Identity
{
    use Authenticatable;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Principal|null Test hook: principal returned by `resolveDefaultPrincipal()`. */
    public ?Principal $defaultPrincipal = null;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's principals.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return $this->newQuery();
    }

    /**
     * Eloquent relation builder for the identity's sessions.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return $this->newQuery();
    }

    /**
     * Application-defined default principal lookup.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        return $this->defaultPrincipal;
    }
}
