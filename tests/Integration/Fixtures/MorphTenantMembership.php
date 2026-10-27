<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D principal fixture whose tenant is a polymorphic (`MorphTo`) relation,
 * named by the `tenant_type` and `tenant_id` columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property ?string $tenant_type
 * @property ?int $tenant_id
 *
 * @internal
 */
final class MorphTenantMembership extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'morph_tenant_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning identity relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ActivatableTenantMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(ActivatableTenantMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation, typed by `tenant_type`.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): MorphTo
    {
        return $this->morphTo();
    }
}
