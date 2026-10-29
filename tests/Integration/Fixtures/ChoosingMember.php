<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 3D identity fixture with no default principal, over the
 * `activatable_tenant_members` rows: a sign-in that names no membership waits
 * for the member to choose one.
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
final class ChoosingMember extends Model implements HasDevices, HasPrincipals, Identity
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_members';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the member's memberships, oldest first.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return ChoosingMembership::query()
            ->where('identity_id', $this->getKey())
            ->orderBy('id');
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
