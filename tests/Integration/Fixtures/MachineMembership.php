<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A service account's membership of a tenant, an activatable tenant unless its
 * `tenant_type` names another: the principal a machine credential acts as,
 * typed by its `type` column, stored in `machine_memberships`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $account_id
 * @property string $tenant_type
 * @property int $tenant_id
 * @property string $type
 * @property bool $is_active
 *
 * @internal
 */
final class MachineMembership extends Model implements CanBeActive, HasType, Principal
{
    use ActsAsPrincipal, ProvidesActiveState, ProvidesType;

    /** @var string|null The table associated with the model. */
    protected $table = 'machine_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The service account that holds the membership.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\MachineAccount, covariant $this>
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(MachineAccount::class, 'account_id');
    }

    /**
     * The tenant the membership acts within, typed by `tenant_type`.
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

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
        ];
    }
}
