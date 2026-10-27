<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Device whose primary key column is `device_uuid` rather than `id`, so the
 * device identifier a token carries is only found again when lookups go by
 * primary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RenamedKeyDevice extends Model implements EloquentDevice
{
    use ActsAsDevice, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'renamed_key_devices';

    /** @var string The primary key for the model. */
    protected $primaryKey = 'device_uuid';

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
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'idle_expires_at'     => 'datetime',
            'absolute_expires_at' => 'datetime',
            'refresh_rotated_at'  => 'datetime',
            'revoked_at'          => 'datetime',
        ];
    }
}
