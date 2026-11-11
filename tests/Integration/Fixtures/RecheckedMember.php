<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * 3D identity that can be deactivated, soft-deleted or given a cutoff after
 * sign-in, acting through `RecheckedMembership`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 *
 * @internal
 */
final class RecheckedMember extends Model implements CanBeActive, HasPrincipals, HasSessions, HasTokensValidAfter, Identity
{
    use Authenticatable, ProvidesActiveState, ProvidesTokensValidAfter, SoftDeletes;

    /** @var string|null The table associated with the model. */
    protected $table = 'rechecked_members';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The member's memberships.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return RecheckedMembership::query()->where('identity_id', $this->getKey());
    }

    /**
     * The member's first membership.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        $principal = $this->principals()->first();

        return $principal instanceof Principal ? $principal : null;
    }

    /**
     * The member's sessions.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return Session::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->id);
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['is_active' => 'boolean', 'tokens_valid_after' => 'datetime'];
    }
}
