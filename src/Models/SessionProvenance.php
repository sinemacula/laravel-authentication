<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * How a session established through an external identity provider began, one
 * row per such session.
 *
 * `provider_context` has no cast, so an application's JSON encoder never
 * changes what is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property string $session_id
 * @property string $connection_id
 * @property ?string $tenant_id
 * @property ?\Carbon\CarbonInterface $provider_authenticated_at
 * @property ?array<array-key, mixed> $accepted_evidence
 * @property ?\Carbon\CarbonInterface $provider_session_expires_at
 * @property ?string $policy_version
 * @property ?string $link_id
 * @property ?string $provider_context
 * @property \Carbon\CarbonInterface $created_at
 */
final class SessionProvenance extends Model
{
    /** @var ?string The name of the "updated at" column: none, a provenance is never updated. */
    public const ?string UPDATED_AT = null;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The primary key: the session's key. */
    protected $primaryKey = 'session_id';

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written with `forceFill()`. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation: the evidence the provider asserted and the provider context. */
    protected $hidden = ['accepted_evidence', 'provider_context'];

    /**
     * Create a provenance on the storage connection, in the configured table.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.proofs.provenance_table', 'authentication_provenance'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
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
            'provider_authenticated_at'   => 'datetime',
            'accepted_evidence'           => 'array',
            'provider_session_expires_at' => 'datetime',
            'created_at'                  => 'datetime',
        ];
    }
}
