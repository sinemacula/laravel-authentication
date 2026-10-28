<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;

/**
 * The live one-time code of one binding (a purpose, a guard, an identifier and,
 * for a verification, an identity): the keyed hash of the code, the issuance it
 * belongs to, the checks made against it, and when it was issued, expires and
 * was used. The row is stored under a keyed digest of its binding, so neither
 * the code nor the identifier can be read back from the table.
 *
 * Kept on the device model's connection, in the table named by
 * `authentication.codes.table`. The code engine writes the rows with single
 * statements of its own; the model exists so `model:prune --model` with this
 * class can delete expired codes.
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
 * @property string $purpose
 * @property string $guard
 * @property string $issue_id
 * @property string $code_hash
 * @property int $attempts
 * @property \Carbon\CarbonInterface $issued_at
 * @property \Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $consumed_at
 */
final class OneTimeCode extends Model
{
    use MassPrunable;

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the binding digest, the issuance and the code's hash. */
    protected $hidden = ['id', 'issue_id', 'code_hash'];

    /**
     * Create a code on the device model's connection, in the configured table.
     * Both are applied here, before Eloquent reads them, so this is
     * construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.codes.table', 'one_time_codes'));
        $this->setConnection(DeviceLookup::model()->getConnectionName());

        parent::__construct($attributes);
    }

    /**
     * The codes that have expired: none can be used any more, and the resend
     * cooldown, never longer than a code's lifetime, has ended with each.
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
            'attempts'    => 'integer',
            'issued_at'   => 'datetime',
            'expires_at'  => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
