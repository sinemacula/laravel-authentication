<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * UUID-keyed 3D identity for a request's caller with no default membership, so
 * a member of two chooses one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CallerMember extends Model implements HasPrincipals, HasSessions, Identity
{
    use Authenticatable, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'caller_members';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The member's memberships, oldest first.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\Tests\Integration\Fixtures\CallerMembership, $this>
     *
     * @formatter:on
     */
    #[\Override]
    public function principals(): HasMany
    {
        return $this->hasMany(CallerMembership::class, 'identity_id')->orderBy('id');
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
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Session, $this>
     *
     * @formatter:on
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }
}
