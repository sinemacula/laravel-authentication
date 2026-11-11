<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;

/**
 * The challenge of one passkey ceremony, used up by the first response to it
 * and pruned by `model:prune` a challenge lifetime after it expires.
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
 * @property ?string $session_id
 * @property ?string $binding_purpose
 * @property array<string, mixed> $options
 * @property \Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $consumed_at
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
     * The challenges that expired, consumed or not, a challenge lifetime ago.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function prunable(): Builder
    {
        $retention = (new PasskeyChallenges(Container::getInstance()->make(Repository::class)))->ttlSeconds();

        return self::query()->where('expires_at', '<=', $this->fromDateTime(Carbon::now()->subSeconds($retention)));
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
            'options'     => 'array',
            'expires_at'  => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
