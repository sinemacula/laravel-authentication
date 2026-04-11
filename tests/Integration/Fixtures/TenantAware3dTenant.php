<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;
use SineMacula\Laravel\Authentication\Traits\ProvidesTenantType;

/**
 * Tenant fixture for the tenant-aware 3D resolution tests.
 *
 * @property int $id
 * @property string $name
 * @property string $type
 *
 * @internal
 */
final class TenantAware3dTenant extends Model implements HasType, Tenant
{
    use ActsAsTenant, ProvidesTenantType;

    /** @var string|null The table associated with the model. */
    protected $table = 'tenant_aware_3d_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
