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
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * The live one-time code challenge of one delivery key (a purpose, a guard, a
 * destination and, where the purpose has one, its owner): the challenge's id
 * and transaction, the keyed hash of its code, the issuance the code belongs
 * to, the checks made against it, the deliveries made to the key in its current
 * window, and when the window began and the code was issued, expires and was
 * used. The row is stored under a keyed digest of its key, so neither the code
 * nor the destination can be read back from the table.
 *
 * Kept on the storage connection (see `Database\StorageConnection`), in the
 * table named by `authentication.codes.table`. The code engine writes the rows
 * with single statements of its own; the model exists so `model:prune --model`
 * with this class can delete expired codes.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the code engine.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $challenge_id
 * @property ?string $context
 * @property string $purpose
 * @property string $guard
 * @property string $issue_id
 * @property string $code_hash
 * @property int $attempts
 * @property int $deliveries
 * @property \Carbon\CarbonInterface $window_started_at
 * @property \Carbon\CarbonInterface $issued_at
 * @property \Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $consumed_at
 */
final class OneTimeCode extends Model
{
    use MassPrunable;

    /** @var bool Whether the model keeps `created_at` and `updated_at`: it keeps neither. */
    public $timestamps = false;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that are not mass assignable: every one, as every column is written by the code engine. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the key's digest, the challenge, its transaction, the issuance and the code's hash. */
    protected $hidden = ['id', 'challenge_id', 'context', 'issue_id', 'code_hash'];

    /**
     * Create a code on the storage connection, in the configured table. Both
     * are applied here, before Eloquent reads them, so this is construction
     * rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.codes.table', 'one_time_codes'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * The codes that have expired and whose delivery window has ended: none can
     * be used any more, the resend cooldown, never longer than a code's
     * lifetime, has ended with each, and deleting one starts no delivery window
     * afresh before its time.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function prunable(): Builder
    {
        $now    = Carbon::now();
        $window = (new CodeSettings(Container::getInstance()->make(Repository::class)))->maxLifetimeSeconds();

        return self::query()
            ->where('expires_at', '<=', $this->fromDateTime($now))
            ->where('window_started_at', '<=', $this->fromDateTime($now->copy()->subSeconds($window)));
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
            'attempts'          => 'integer',
            'deliveries'        => 'integer',
            'window_started_at' => 'datetime',
            'issued_at'         => 'datetime',
            'expires_at'        => 'datetime',
            'consumed_at'       => 'datetime',
        ];
    }
}
