<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesDeactivationTime;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Membership fixture of a `DeactivatableMember`, over the
 * `deactivatable_memberships` rows, that records its deactivation as an
 * `immutable_datetime` in `deactivated_at` and acts within a
 * `DeactivatableTenant`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property int $tenant_id
 * @property ?\Carbon\CarbonImmutable $deactivated_at
 *
 * @internal
 */
final class DeactivatableMembership extends Model implements CanBeActive, Principal
{
    use ActsAsPrincipal, ProvidesDeactivationTime;

    /** @var string|null The table associated with the model. */
    protected $table = 'deactivatable_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning member relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\DeactivatableMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(DeactivatableMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\DeactivatableTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(DeactivatableTenant::class, 'tenant_id');
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'deactivated_at' => 'immutable_datetime',
        ];
    }
}
