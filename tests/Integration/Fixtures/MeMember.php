<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D identity fixture for the `me` route binding: UUID-keyed, so its sessions'
 * owner column compares as text on every database, with its memberships and
 * sessions as Eloquent relations, so scoped child bindings reach them, a
 * relation that holds only some of its sessions, one that reads its sessions
 * while it is built, and no default membership, so a member of two chooses one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MeMember extends Model implements HasPrincipals, HasSessions, Identity
{
    use Authenticatable, HasUuids, ResolvesMeRouteBinding;

    /** @var string The client name of the sessions `oldSessions()` holds. */
    public const string OLD_CLIENT = 'old';

    /** @var string|null The table associated with the model. */
    protected $table = 'me_members';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The member's memberships, oldest first.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\Tests\Integration\Fixtures\MeMembership, $this>
     *
     * @formatter:on
     */
    #[\Override]
    public function principals(): HasMany
    {
        return $this->hasMany(MeMembership::class, 'identity_id')->orderBy('id');
    }

    /**
     * The member has no default membership.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        return null;
    }

    /**
     * The member's sessions.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\Tests\Integration\Fixtures\MeSession, $this>
     *
     * @formatter:on
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        return $this->morphMany(MeSession::class, 'authenticatable');
    }

    /**
     * The member's sessions from the client named `old`: a relationship that
     * leaves its other sessions out.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\Tests\Integration\Fixtures\MeSession, $this>
     *
     * @formatter:on
     */
    public function oldSessions(): MorphMany
    {
        return $this->morphMany(MeSession::class, 'authenticatable')->where('client_name', self::OLD_CLIENT);
    }

    /**
     * The member's sessions by the keys read while the relationship is built: a
     * relationship whose constraints come from a query.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\Tests\Integration\Fixtures\MeSession, $this>
     *
     * @formatter:on
     */
    public function listedSessions(): MorphMany
    {
        return $this->morphMany(MeSession::class, 'authenticatable')->whereKey($this->sessions()->pluck('id')->all());
    }
}
