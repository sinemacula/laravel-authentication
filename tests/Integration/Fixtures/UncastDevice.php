<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Custom device model over the shipped `devices` table that uses the
 * `ActsAsDevice` trait but declares no casts, so `revoked_at` reads back as the
 * raw value the database returns rather than a Carbon instance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UncastDevice extends Model implements EloquentDevice
{
    use ActsAsDevice, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'devices';

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
}
