<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Principal fixture for the `me` route binding: a soft-deleting membership of a
 * `MeMember`, acting within no tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MeMembership extends Model implements Principal
{
    use ActsAsPrincipal, ResolvesMeRouteBinding, SoftDeletes;

    /** @var string|null The table associated with the model. */
    protected $table = 'me_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning member relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\MeMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(MeMember::class, 'identity_id');
    }
}
