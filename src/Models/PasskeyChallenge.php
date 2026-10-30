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
 * The challenge of one passkey ceremony (a registration, a sign-in or a
 * factor): which guard and relying party it is for, the identity it is bound to
 * (none for a usernameless sign-in), the options sent to the browser, which
 * carry the challenge, and until when it may be answered. It is used up by the
 * first response made to it, whatever that response proves.
 *
 * Kept on the storage connection (see `Database\StorageConnection`), in the
 * table named by `authentication.passkeys.challenges_table`. Expired challenges
 * are pruned by Laravel's `model:prune --model` with this class.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the passkey service.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $purpose
 * @property string $guard
 * @property string $rp_id
 * @property ?string $authenticatable_type
 * @property ?string $authenticatable_id
 * @property array<string, mixed> $options
 * @property \Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $created_at
 */
final class PasskeyChallenge extends Model
{
    use MassPrunable;

    /** @var ?string The name of the "updated at" column: none, a challenge is never updated. */
    public const ?string UPDATED_AT = null;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written by the passkey service. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['options'];

    /**
     * Create a challenge on the storage connection, in the configured table.
     * Both are applied here, before Eloquent reads them, so this is
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
        $this->setTable(Config::string('authentication.passkeys.challenges_table', 'passkey_challenges'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * The challenges that have expired, which can no longer be answered.
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
            'options'    => 'array',
            'expires_at' => 'datetime',
        ];
    }
}
