<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Concerns\PrunesSessions;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * The package's default Eloquent session, swappable through
 * `authentication.session.model`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $generation
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property ?string $principal_type
 * @property ?string $principal_id
 * @property string $status
 * @property ?list<string> $requires
 * @property ?string $pending_key
 * @property ?string $supersedes_session_id
 * @property ?string $supersedes_refresh_key
 * @property ?list<array<string, string>> $attempt_windows
 * @property ?string $tenant_id
 * @property ?string $tenant_policy_version
 * @property ?\Carbon\CarbonInterface $switched_at
 * @property int $issuance_sequence
 * @property ?string $guard
 * @property ?string $sign_in_method
 * @property ?string $sign_in_identifier_type
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
 * @property \Carbon\CarbonInterface $signed_in_at
 * @property \Carbon\CarbonInterface $idle_expires_at
 * @property ?\Carbon\CarbonInterface $absolute_expires_at
 * @property ?\Carbon\CarbonInterface $revoked_at
 * @property ?string $revoked_reason
 *
 * @inheritable
 */
class Session extends Model implements EloquentSession
{
    use ActsAsSession, HasUuids, PrunesSessions;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'client_name',
        'platform',
    ];

    /** @var array<string, mixed> The column defaults a new session reads before it is saved, as the migration's. */
    protected $attributes = [
        'status' => 'active',
    ];

    /**
     * Create a session bound to the configured table and, unless the class
     * names a connection of its own, the storage connection.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable($this->resolveConfiguredTable());
        $this->connection ??= $this->resolveStorageConnection();

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
     * Polymorphic relation to the principal the session acts as.
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
            'generation'              => 'string',
            'authenticatable_type'    => 'string',
            'authenticatable_id'      => 'string',
            'principal_type'          => 'string',
            'principal_id'            => 'string',
            'status'                  => 'string',
            'requires'                => 'array',
            'pending_key'             => 'string',
            'supersedes_session_id'   => 'string',
            'supersedes_refresh_key'  => 'string',
            'attempt_windows'         => 'array',
            'tenant_id'               => 'string',
            'tenant_policy_version'   => 'string',
            'switched_at'             => 'datetime',
            'issuance_sequence'       => 'integer',
            'guard'                   => 'string',
            'sign_in_method'          => 'string',
            'sign_in_identifier_type' => 'string',
            'client_name'             => 'string',
            'platform'                => 'string',
            'created_ip'              => 'string',
            'created_user_agent'      => 'string',
            'last_used_at'            => 'datetime',
            'last_used_ip'            => 'string',
            'last_used_user_agent'    => 'string',
            'refresh_key'             => 'string',
            'previous_refresh_key'    => 'string',
            'refresh_rotated_at'      => 'datetime',
            'signed_in_at'            => 'datetime',
            'idle_expires_at'         => 'datetime',
            'absolute_expires_at'     => 'datetime',
            'revoked_at'              => 'datetime',
            'revoked_reason'          => 'string',
        ];
    }

    /**
     * Read the configured session table, or the default before the Config
     * facade is bootstrapped.
     *
     * @return string
     */
    private function resolveConfiguredTable(): string
    {
        try {
            $table = Config::string('authentication.session.table', 'authentication_sessions');
        } catch (\Throwable) {
            return 'authentication_sessions';
        }

        return $table === '' ? 'authentication_sessions' : $table;
    }

    /**
     * Read the storage connection, or `null` (the default connection) before
     * the Config facade is bootstrapped.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function resolveStorageConnection(): ?string
    {
        return Config::getFacadeRoot() === null ? null : StorageConnection::name();
    }
}
