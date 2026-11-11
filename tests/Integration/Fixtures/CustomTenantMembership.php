<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Membership that implements `Principal` without `ActsAsPrincipal`, reading its
 * tenant from a relation of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property int $tenant_id
 *
 * @internal
 */
final class CustomTenantMembership extends Model implements Principal
{
    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenant_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Return the membership's key.
     *
     * @return mixed
     */
    #[\Override]
    public function getPrincipalIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * Return the member that owns the membership.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        $identity = $this->getAttribute('identity');

        return $identity instanceof Identity ? $identity : throw new \LogicException('The membership has no member.');
    }

    /**
     * Return the tenant the membership acts within, read from its `tenant`
     * relation.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function getTenant(): ?Tenant
    {
        $tenant = $this->getAttribute('tenant');

        return $tenant instanceof Tenant ? $tenant : null;
    }

    /**
     * Owning member relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ChoosingMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(ChoosingMember::class, 'identity_id');
    }

    /**
     * Acting tenant relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ActivatableTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(ActivatableTenant::class, 'tenant_id');
    }
}
