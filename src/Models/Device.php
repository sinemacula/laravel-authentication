<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Device as DeviceContract;
use SineMacula\Laravel\Authentication\Traits\ActsAsDevice;

/**
 * Default shipped Device Eloquent model.
 *
 * Polymorphic device record bound to an authenticatable identity via
 * the `authenticatable()` morphTo relation. UUID v7 primary key. Swappable via
 * `config('authentication.device.model')` / `device.table`. Non-`final` so
 * consumers may subclass; subclasses MUST preserve the `authenticatable()`
 * morphTo and `getRefreshKey()` accessor for refresh-token rotation to work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property string $id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $os
 * @property ?string $refresh_key
 * @property \Carbon\CarbonInterface|null $revoked_at
 * @property \Carbon\CarbonInterface|null $last_logged_in_at
 * @property \Carbon\CarbonInterface|null $last_mfa_verified_at
 */
class Device extends Model implements DeviceContract
{
    use ActsAsDevice, HasUuids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'os',
        'refresh_key',
        'revoked_at',
        'last_logged_in_at',
        'last_mfa_verified_at',
    ];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'revoked_at'           => 'datetime',
        'last_logged_in_at'    => 'datetime',
        'last_mfa_verified_at' => 'datetime',
    ];

    /**
     * Create a new Device bound to the package-configured table name. Reads the
     * table name lazily on each instantiation so runtime config swaps (tests,
     * tenancy) take effect immediately.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable($this->resolveConfiguredTable());

        parent::__construct($attributes);
    }

    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Columns that receive a generated unique identifier on insert.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return ['id'];
    }

    /**
     * Read the configured device table, falling back to `'devices'` when the
     * key is absent or the Config facade is not yet bootstrapped.
     *
     * @return string
     */
    private function resolveConfiguredTable(): string
    {
        try {
            $table = Config::string('authentication.device.table', 'devices');
        } catch (\Throwable) {
            return 'devices';
        }

        return $table === '' ? 'devices' : $table;
    }
}
