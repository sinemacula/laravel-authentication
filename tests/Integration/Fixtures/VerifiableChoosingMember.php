<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 3D identity fixture, like `ChoosingMember`, with no default membership, that
 * reports its email verified only when its `email_verified` column, which the
 * test adds, is set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $email_verified
 *
 * @internal
 */
final class VerifiableChoosingMember extends Model implements HasDevices, HasPrincipals, HasVerifiableIdentifiers, Identity
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
            ->where('authenticatable_id', (string) $this->id);
    }

    /**
     * The member's email, its only identifier.
     *
     * @param  string  $type
     * @return ?string
     */
    #[\Override]
    public function getIdentifierForVerification(string $type): ?string
    {
        return $type === 'email' ? $this->email : null;
    }

    /**
     * Whether the member's email is verified.
     *
     * @param  string  $type
     * @return bool
     */
    #[\Override]
    public function hasVerifiedIdentifier(string $type): bool
    {
        return $type === 'email' && $this->email_verified;
    }

    /**
     * Mark the email verified.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        return $this->forceFill(['email_verified' => true])->save();
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['email_verified' => 'boolean'];
    }
}
