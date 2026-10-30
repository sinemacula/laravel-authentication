<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 3D identity fixture over the `activatable_tenant_members` rows whose
 * `principals()` reads all of the member's roles, so it yields the roles that
 * are not principals beside the memberships that are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class RoleMember extends Model implements HasDevices, HasPrincipals, Identity
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_members';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for every role of the member, oldest first,
     * each membership read as a `MemberRoleMembership`.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return MemberRole::query()
            ->where('identity_id', $this->getKey())
            ->orderBy('id')
            ->afterQuery(static fn (Collection $roles): Collection => $roles->map(
                static fn (MemberRole $role): Model => $role->kind === 'membership'
                    ? (new MemberRoleMembership)->newFromBuilder($role->getAttributes(), $role->getConnectionName())
                    : $role,
            ));
    }

    /**
     * The member has no default role.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        return null;
    }

    /**
     * Eloquent relation builder for the member's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
