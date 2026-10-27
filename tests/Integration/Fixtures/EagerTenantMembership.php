<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D membership over the activatable tenant tables that eager-loads its tenant
 * on every query, so the tenant behind the activity check is loaded alongside
 * the hinted principal lookup rather than lazily.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EagerTenantMembership extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var list<string> The relations to eager load on every query. */
    protected $with = ['tenant'];

    /**
     * Owning identity relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\EagerTenantMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(EagerTenantMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ActivatableTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(ActivatableTenant::class, 'tenant_id');
    }
}
