<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
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
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @property string               $id
 * @property string               $authenticatable_type
 * @property string               $authenticatable_id
 * @property string               $os
 * @property string               $refresh_key
 * @property \Carbon\Carbon|null $last_logged_in_at
 * @property \Carbon\Carbon|null $last_mfa_verified_at
 */
class Device extends Model implements DeviceContract
{
    use ActsAsDevice;
    use HasUlids;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'last_logged_in_at'    => 'datetime',
        'last_mfa_verified_at' => 'datetime',
    ];

    /**
     * Create a new Device instance reading its table name from package
     * config so consumers may remap the underlying table without
     * subclassing.
     *
     * @param  array<string, mixed> $attributes Initial attribute values.
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable((string) config('laravel-authentication.device.table', 'devices'));

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
    public function uniqueIds(): array
    {
        return ['id'];
    }
}
