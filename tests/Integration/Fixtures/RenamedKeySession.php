<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Session whose primary key column is `session_uuid` instead of `id`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RenamedKeySession extends Model implements EloquentSession
{
    use ActsAsSession, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'renamed_key_sessions';

    /** @var string The primary key for the model. */
    protected $primaryKey = 'session_uuid';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

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
        return [
            'idle_expires_at'     => 'datetime',
            'absolute_expires_at' => 'datetime',
            'refresh_rotated_at'  => 'datetime',
            'revoked_at'          => 'datetime',
        ];
    }
}
