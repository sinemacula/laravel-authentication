<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Membership fixture of a `KeyedTenantMember`, over the `keyed_memberships`
 * rows, whose uncast string `tenant_id` names a `TypedTenant`: a key such as
 * `'05'` the database matches against the tenant's integer key while PHP does
 * not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property ?string $tenant_id
 *
 * @internal
 */
final class KeyedTenantMembership extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'keyed_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning member relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\KeyedTenantMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(KeyedTenantMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\TypedTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(TypedTenant::class, 'tenant_id');
    }
}
