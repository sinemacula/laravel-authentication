<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Traits\ActsAsDevice;

/**
 * Eloquent stub implementing the package's Device contract.
 *
 * Configurable table for in-memory sqlite tests; defaults to `stub_devices` so
 * it never collides with the package's own `devices` table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property string $id
 * @property string $os
 * @property ?string $refresh_key
 * @property \Carbon\CarbonInterface|null $revoked_at
 * @property \Carbon\CarbonInterface|null $last_logged_in_at
 * @property \Carbon\CarbonInterface|null $last_mfa_verified_at
 *
 * @internal
 */
class StubDevice extends Model implements Device
{
    use ActsAsDevice;
    use HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_devices';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'revoked_at'           => 'datetime',
        'last_logged_in_at'    => 'datetime',
        'last_mfa_verified_at' => 'datetime',
    ];
}
