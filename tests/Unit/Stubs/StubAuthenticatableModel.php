<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent model implementing Authenticatable directly via Laravel's
 * trait. Used by ModelProviderTest where Mockery against the contract
 * does not provide enough surface for retrieveById/retrieveByCredentials
 * coverage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
class StubAuthenticatableModel extends Model implements AuthenticatableContract
{
    use Authenticatable;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
