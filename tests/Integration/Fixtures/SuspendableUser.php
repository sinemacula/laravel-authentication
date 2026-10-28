<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D fixture whose activity check reads the database: it is inactive while a
 * row in `user_suspensions` names it, as an application might record a ban or a
 * lapsed subscription outside the user row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SuspendableUser extends Model implements CanBeActive, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'suspendable_users';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Whether no suspension currently names the user.
     *
     * @return bool
     */
    #[\Override]
    public function isActive(): bool
    {
        return !$this->getConnection()
            ->table('user_suspensions')
            ->where('user_id', $this->getKey())
            ->exists();
    }
}
