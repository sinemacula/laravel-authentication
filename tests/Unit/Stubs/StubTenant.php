<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;
use SineMacula\Laravel\Authentication\Traits\ProvidesTenantType;

/**
 * Eloquent stub implementing the `Tenant` contract plus the
 * optional `HasType` capability via the package traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
class StubTenant extends Model implements HasType, Tenant
{
    use ActsAsTenant;
    use ProvidesTenantType;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
