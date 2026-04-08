<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Device as DeviceContract;
use SineMacula\Laravel\Authentication\Traits\ActsAsDevice;

/**
 * Default shipped Device Eloquent model.
 *
 * Polymorphic device record bound to an authenticatable identity via
 * the `authenticatable()` morphTo relation. Uses a ULID primary key
 * (NFR-10). Swappable via `config('laravel-authentication.device.model')`
 * and `device.table`.
 *
 * Intentionally non-`final` so consumers can either point
 * `device.model` at a subclass that adds domain columns/relations or
 * extend the shipped model directly. Subclasses MUST keep the
 * `authenticatable()` morphTo and the `getRefreshKey()` accessor
 * intact for the refresh-token rotation flow to work.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
    use ActsAsDevice;
    use HasUlids;

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
     * Create a new Device instance bound to the package-configured
     * table name. Reads the table name lazily from the Config facade
     * on each instantiation so consumers that swap
     * `laravel-authentication.device.table` at runtime (tests,
     * runtime tenancy) observe the new value immediately without
     * touching a process-wide cache.
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
     * Read the configured device table from the package config,
     * falling back to `'devices'` when the key is absent or the
     * Config facade is not bootstrapped (e.g. during certain unit
     * tests that instantiate models before the Testbench container
     * is ready).
     *
     * @return string
     */
    private function resolveConfiguredTable(): string
    {
        try {
            $table = Config::string('laravel-authentication.device.table', 'devices');
        } catch (\Throwable) {
            return 'devices';
        }

        return $table === '' ? 'devices' : $table;
    }
}
