<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D principal fixture over the `ActivatableTenantMembership` table whose
 * tenant relation is declared with `withDefault()`, so a missing tenant row
 * comes back as an unsaved placeholder rather than `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property int $tenant_id
 *
 * @internal
 */
final class DefaultTenantMembership extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_memberships';

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
     * Acting tenant relation, returning an unsaved tenant for a missing row.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ActivatableTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(ActivatableTenant::class, 'tenant_id')->withDefault();
    }
}
