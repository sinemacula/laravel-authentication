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
 * One attempt counter: how many attempts a key has made in the window that ends
 * at `window_ends_at`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $key
 * @property int $hits
 * @property \Carbon\CarbonInterface $window_ends_at
 */
final class RateLimit extends Model
{
    use MassPrunable;

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string The primary key for the model. */
    protected $primaryKey = 'key';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /**
     * Create a counter bound to the configured table and rate-limit connection.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.rate_limits.table', 'rate_limits'));
        $this->setConnection(StorageConnection::forRateLimits());

        parent::__construct($attributes);
    }

    /**
     * Counters whose window has ended.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     */
    public function prunable(): Builder
    {
        return self::query()->where('window_ends_at', '<=', Carbon::now());
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
            'hits'           => 'integer',
            'window_ends_at' => 'datetime',
        ];
    }
}
