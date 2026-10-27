<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;

/**
 * One attempt counter: how many attempts a key (a SHA-256 digest of the guard,
 * the flow, the scope and the identifier or IP address) has made in the window
 * that ends at `window_ends_at`.
 *
 * The table and connection come from `authentication.rate_limits`. The limiter
 * writes the counters with single statements of its own; the model exists so
 * `model:prune` can delete counters whose window has ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $key
 * @property int $hits
 * @property \Carbon\CarbonInterface $window_ends_at
 *
 * @internal
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
     * Create a counter bound to the configured table and connection, read on
     * each instantiation so runtime config changes take effect at once. The
     * table and connection have to be applied before Eloquent reads them, so
     * this is construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $connection = Config::get('authentication.rate_limits.connection');

        $this->setTable(Config::string('authentication.rate_limits.table', 'rate_limits'));
        $this->setConnection(is_string($connection) && $connection !== '' ? $connection : null);

        parent::__construct($attributes);
    }

    /**
     * Counters whose window has ended: the limiter starts a new one on the next
     * attempt anyway, so they are safe to delete.
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
