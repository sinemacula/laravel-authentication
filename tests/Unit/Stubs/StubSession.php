<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Eloquent session stub on the `stub_sessions` table unless one is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property ?string $refresh_key
 * @property ?string $previous_refresh_key
 * @property \Carbon\CarbonInterface|null $refresh_rotated_at
 * @property \Carbon\CarbonInterface|null $idle_expires_at
 * @property \Carbon\CarbonInterface|null $absolute_expires_at
 * @property \Carbon\CarbonInterface|null $revoked_at
 * @property ?string $revoked_reason
 * @property \Carbon\CarbonInterface|null $last_used_at
 * @property ?string $last_used_ip
 * @property ?string $last_used_user_agent
 *
 * @internal
 *
 * @inheritable
 */
class StubSession extends Model implements EloquentSession
{
    use ActsAsSession, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_sessions';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Polymorphic relation to the owning authenticatable identity.
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
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'refresh_rotated_at'  => 'datetime',
            'idle_expires_at'     => 'datetime',
            'absolute_expires_at' => 'datetime',
            'revoked_at'          => 'datetime',
            'last_used_at'        => 'datetime',
        ];
    }
}
