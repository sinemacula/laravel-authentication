<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D principal fixture with an activity flag of its own, owned by an
 * `ActivatableTenantMember` (which holds devices), in the `active_memberships`
 * table the test creates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property bool $is_active
 *
 * @internal
 */
final class ActiveMembership extends Model implements CanBeActive, Principal
{
    use ActsAsPrincipal, ProvidesActiveState;

    /** @var string|null The table associated with the model. */
    protected $table = 'active_memberships';

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
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['is_active' => 'boolean'];
    }
}
