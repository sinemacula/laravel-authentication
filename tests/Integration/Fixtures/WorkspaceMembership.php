<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Membership fixture, over the `activatable_tenant_memberships` rows, whose
 * tenant relation is renamed `workspace` and names a `ParentedTenant`.
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
final class WorkspaceMembership extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning member relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ChoosingMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(ChoosingMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation, under the name `getTenantRelationName()` gives.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ParentedTenant, covariant $this>
     *
     * @formatter:on
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(ParentedTenant::class, 'tenant_id');
    }

    /**
     * Return the relation name resolving to the acting tenant.
     *
     * @return string
     */
    protected function getTenantRelationName(): string
    {
        return 'workspace';
    }
}
