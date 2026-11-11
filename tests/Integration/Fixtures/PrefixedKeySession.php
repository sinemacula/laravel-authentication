<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\ValidatesSessionKey;

/**
 * Session model keyed by `dev_` strings, a format it describes through
 * `ValidatesSessionKey`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrefixedKeySession extends Model implements EloquentSession, ValidatesSessionKey
{
    use ActsAsSession;

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string|null The table associated with the model. */
    protected $table = 'prefixed_key_sessions';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Whether the value is a `dev_` key.
     *
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function isValidSessionKey(mixed $key): bool
    {
        return is_string($key) && preg_match('/^dev_[a-z0-9]{8}$/', $key) === 1;
    }

    /**
     * The identity that owns the session.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        return $this->morphTo(); // @phpstan-ignore return.type
    }

    /**
     * Polymorphic relation to the principal the session acts as.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function principal(): MorphTo
    {
        return $this->morphTo(); // @phpstan-ignore return.type
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['revoked_at' => 'datetime'];
    }
}
