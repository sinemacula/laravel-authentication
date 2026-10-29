<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Default shipped Device Eloquent model.
 *
 * Polymorphic device record bound to an authenticatable identity via the
 * `authenticatable()` morphTo relation, and optionally to the principal it acts
 * as via `principal()`. UUID v7 primary key. Swappable via
 * `config('authentication.device.model')` / `device.table` as the package's
 * default Eloquent adapter. Non-`final` so consumers may subclass; subclasses
 * that remain refreshable MUST continue satisfying the `EloquentDevice`
 * persistence boundary.
 *
 * Only the client-described metadata is mass assignable. Ownership, the
 * request-derived columns, and the session state (digests, rotation time,
 * deadlines, revocation, last use) are not: the package writes the columns it
 * owns with query-builder updates, and code that creates a device sets the rest
 * with `forceFill()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property ?string $principal_type
 * @property ?string $principal_id
 * @property ?string $guard
 * @property ?string $sign_in_method
 * @property ?string $client_name
 * @property ?string $platform
 * @property ?string $created_ip
 * @property ?string $created_user_agent
 * @property ?\Carbon\CarbonInterface $last_used_at
 * @property ?string $last_used_ip
 * @property ?string $last_used_user_agent
 * @property ?string $refresh_key
 * @property ?string $previous_refresh_key
 * @property ?\Carbon\CarbonInterface $refresh_rotated_at
 * @property \Carbon\CarbonInterface $idle_expires_at
 * @property \Carbon\CarbonInterface $absolute_expires_at
 * @property ?\Carbon\CarbonInterface $revoked_at
 * @property ?string $revoked_reason
 *
 * @inheritable
 */
class Device extends Model implements EloquentDevice
{
    use ActsAsDevice, HasUuids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'client_name',
        'platform',
    ];

    /**
     * Create a new Device bound to the package-configured table name. Reads the
     * table name lazily on each instantiation so runtime config swaps (tests,
     * tenancy) take effect immediately. The table has to be applied here,
     * before Eloquent reads it, so this is construction rather than model
     * behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable($this->resolveConfiguredTable());

        parent::__construct($attributes);
    }

    /**
     * Polymorphic relation to the owning authenticatable identity.
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
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'principal_type'       => 'string',
            'principal_id'         => 'string',
            'guard'                => 'string',
            'sign_in_method'       => 'string',
            'client_name'          => 'string',
            'platform'             => 'string',
            'created_ip'           => 'string',
            'created_user_agent'   => 'string',
            'last_used_at'         => 'datetime',
            'last_used_ip'         => 'string',
            'last_used_user_agent' => 'string',
            'refresh_key'          => 'string',
            'previous_refresh_key' => 'string',
            'refresh_rotated_at'   => 'datetime',
            'idle_expires_at'      => 'datetime',
            'absolute_expires_at'  => 'datetime',
            'revoked_at'           => 'datetime',
            'revoked_reason'       => 'string',
        ];
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
