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
 * The pending change of one identity's identifier of one type, pruned by
 * `model:prune` once expired.
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
     * Create a pending change on the storage connection, in the configured
     * table.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.identifier_changes.table', 'identifier_changes'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * The pending changes that have expired.
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
