<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;

/**
 * A recorded revocation of a device, kept outside the device row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $device_id
 * @property \Carbon\CarbonInterface $revoked_at
 *
 * @internal
 */
final class DeviceRevocation extends Model
{
    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var string|null The table associated with the model. */
    protected $table = 'device_revocations';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'revoked_at' => 'datetime',
        ];
    }
}
