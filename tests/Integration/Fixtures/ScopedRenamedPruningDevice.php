<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Concerns\PrunesDevices;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Custom device model that opts into pruning, with its revocation time and
 * deadlines in renamed columns and a global scope that keeps it to the `api`
 * guard's devices, so pruning must take its columns from the name accessors and
 * keep its conditions grouped inside the scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopedRenamedPruningDevice extends Model implements EloquentDevice
{
    use ActsAsDevice, HasUuids, PrunesDevices;

    /** @var string|null The table associated with the model. */
    protected $table = 'scoped_renamed_pruning_devices';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity that owns the device.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        return $this->morphTo(); // @phpstan-ignore return.type
    }

    /**
     * Polymorphic relation to the principal the device's session acts as.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function principal(): MorphTo
    {
        return $this->morphTo(); // @phpstan-ignore return.type
    }

    /**
     * Column name holding the revocation timestamp.
     *
     * @return string
     */
    #[\Override]
    public function getRevokedAtName(): string
    {
        return 'ended_at';
    }

    /**
     * Column name holding the idle deadline.
     *
     * @return string
     */
    #[\Override]
    public function getIdleExpiresAtName(): string
    {
        return 'idle_until';
    }

    /**
     * Column name holding the absolute deadline.
     *
     * @return string
     */
    #[\Override]
    public function getAbsoluteExpiresAtName(): string
    {
        return 'valid_until';
    }

    /**
     * Keep every query to the `api` guard's devices.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope('api', static function (Builder $query): void {
            $query->where('guard', 'api');
        });
    }
}
