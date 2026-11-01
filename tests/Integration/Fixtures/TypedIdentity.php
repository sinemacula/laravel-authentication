<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * 3D identity fixture whose memberships have a `type` column of their own and
 * may act within a tenant.
 *
 * Its default principal is its first membership.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TypedIdentity extends Model implements HasPrincipals, HasSessions, Identity
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'typed_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's memberships.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return TypedMembership::query()->where('identity_id', $this->getKey());
    }

    /**
     * Resolve the identity's first membership.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        /** @var ?\Tests\Integration\Fixtures\TypedMembership */
        return $this->principals()->orderBy('id')->first();
    }

    /**
     * Eloquent relation builder for the identity's sessions.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return Session::query()
            ->where('authenticatable_type', $this->getMorphClass())
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
