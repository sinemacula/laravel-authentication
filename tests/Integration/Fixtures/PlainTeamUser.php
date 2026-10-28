<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D user whose `tenant` relation points at an ordinary team model rather than
 * a `Tenant`, so it acts within no tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property int $team_id
 *
 * @internal
 */
final class PlainTeamUser extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'plain_team_users';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The team the user belongs to.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\PlainTeam, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(PlainTeam::class, 'team_id');
    }
}
