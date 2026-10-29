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
 * The pending change of one identity's identifier of one type: the guard it was
 * requested through, the identifier it would replace and the one it would set,
 * the request its code or link is bound to, and when it was requested and
 * expires. One row per identity and type, stored under a digest of the two, so
 * a new request replaces the one before.
 *
 * Kept on the device model's connection, so confirming a change, using its code
 * and invalidating the proofs it outdates are one transaction, in the table
 * named by `authentication.identifier_changes.table`. The identifier change
 * service writes the rows with single statements of its own; the model exists
 * so `model:prune --model` with this class can delete expired changes.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the identifier change service.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $guard
 * @property string $type
 * @property ?string $previous
 * @property bool $previous_verified
 * @property string $identifier
 * @property string $request_id
 * @property \Carbon\CarbonInterface $requested_at
 * @property \Carbon\CarbonInterface $expires_at
 */
final class IdentifierChange extends Model
{
    use MassPrunable;

    /** @var bool Whether the model keeps `created_at` and `updated_at`: it keeps neither. */
    public $timestamps = false;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that are not mass assignable: every one, as every column is written by the service. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the row's digest, the identifiers and the request the proofs are bound to. */
    protected $hidden = ['id', 'previous', 'identifier', 'request_id'];

    /**
     * Create a pending change on the device model's connection, in the
     * configured table. Both are applied here, before Eloquent reads them, so
     * this is construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.identifier_changes.table', 'identifier_changes'));
        $this->setConnection(DeviceLookup::model()->getConnectionName());

        parent::__construct($attributes);
    }

    /**
     * The pending changes that have expired: neither their code nor their link
     * can confirm them any more.
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
            'previous_verified' => 'boolean',
            'requested_at'      => 'datetime',
            'expires_at'        => 'datetime',
        ];
    }
}
