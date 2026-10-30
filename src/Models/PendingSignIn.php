<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * A sign-in waiting for a further factor, or for its identity to choose the
 * principal it acts as: who signed in, as which principal (none yet for a
 * choice), through which guard and method, from which client, on which proven
 * device, and until when the pending credential that continues it is valid.
 *
 * Kept on the storage connection (see `Database\StorageConnection`) with the
 * devices, so completing it and writing the session are one transaction, in the
 * table named by `authentication.sign_in.pending_table`. Rows whose credential
 * has expired are pruned by Laravel's `model:prune --model` with this class.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the session service.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $token_digest
 * @property string $purpose
 * @property string $guard
 * @property string $sign_in_method
 * @property ?string $identifier_type
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property ?string $principal_type
 * @property ?string $principal_id
 * @property ?string $client_name
 * @property ?string $platform
 * @property ?string $created_ip
 * @property ?string $created_user_agent
 * @property ?string $device_id
 * @property ?string $device_refresh_key
 * @property ?list<array<string, string>> $attempt_windows
 * @property \Carbon\CarbonInterface $expires_at
 */
final class PendingSignIn extends Model
{
    use MassPrunable;

    /** @var string Purpose of a pending sign-in waiting for a further factor. */
    public const string ADDITIONAL_FACTOR = 'additional_factor';

    /** @var string Purpose of a pending sign-in waiting for its identity to choose a principal. */
    public const string PRINCIPAL_CHOICE = 'principal_choice';

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written with `forceFill()`. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['token_digest', 'device_refresh_key', 'attempt_windows'];

    /**
     * Create a pending sign-in on the storage connection, in the configured
     * table. Both are applied here, before Eloquent reads them, so this is
     * construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.sign_in.pending_table', 'pending_sign_ins'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * The pending sign-ins whose credential has expired.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     */
    public function prunable(): Builder
    {
        return self::query()->where('expires_at', '<=', $this->fromDateTime(Carbon::now()));
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
            'attempt_windows' => 'array',
            'expires_at'      => 'datetime',
        ];
    }
}
