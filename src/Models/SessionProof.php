<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * One proof recorded on a session, never changed once written except to void
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $sequence
 * @property string $id
 * @property string $session_id
 * @property string $kind
 * @property string $purpose
 * @property string $method
 * @property string $channel_kind
 * @property ?string $channel_reference
 * @property ?string $factor_reference
 * @property ?bool $user_presence
 * @property ?bool $user_verification
 * @property ?bool $backup_eligible
 * @property ?bool $backup_state
 * @property ?bool $phishing_resistant
 * @property ?string $key_protection
 * @property ?bool $accepted
 * @property ?bool $multifactor
 * @property ?bool $additional_verification
 * @property ?array<array-key, mixed> $evidence
 * @property list<string> $methods
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $guard
 * @property \Carbon\CarbonInterface $authenticated_at
 * @property ?\Carbon\CarbonInterface $voided_at
 * @property \Carbon\CarbonInterface $created_at
 */
final class SessionProof extends Model
{
    /** @var ?string The name of the "updated at" column: none, a proof is never updated. */
    public const ?string UPDATED_AT = null;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written with `forceFill()`. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation: a code's destination, the factor used and a provider's evidence. */
    protected $hidden = ['channel_reference', 'factor_reference', 'evidence'];

    /**
     * Create a proof on the storage connection, in the configured table.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.proofs.table', 'authentication_proofs'));
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
            'user_presence'           => 'boolean',
            'user_verification'       => 'boolean',
            'backup_eligible'         => 'boolean',
            'backup_state'            => 'boolean',
            'phishing_resistant'      => 'boolean',
            'accepted'                => 'boolean',
            'multifactor'             => 'boolean',
            'additional_verification' => 'boolean',
            'evidence'                => 'array',
            'methods'                 => 'array',
            'authenticated_at'        => 'datetime',
            'voided_at'               => 'datetime',
            'created_at'              => 'datetime',
        ];
    }
}
