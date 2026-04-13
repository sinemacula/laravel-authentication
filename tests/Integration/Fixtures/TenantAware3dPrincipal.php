<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;

/**
 * Principal fixture for tenant-aware 3D resolution tests.
 *
 * @property int $id
 * @property int $identity_id
 * @property int $tenant_id
 * @property string $name
 * @property bool $is_active
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantAware3dPrincipal extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'tenant_aware_3d_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'identity_id' => 'integer',
        'tenant_id'   => 'integer',
        'is_active'   => 'boolean',
    ];

    /**
     * Owning identity relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\TenantAware3dIdentity, covariant
     *     $this>
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(TenantAware3dIdentity::class, 'identity_id');
    }

    /**
     * Acting tenant relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\TenantAware3dTenant, covariant
     *     $this>
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(TenantAware3dTenant::class, 'tenant_id');
    }
}
