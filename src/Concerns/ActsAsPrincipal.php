<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * Provides default Principal contract implementations sourced from configurable
 * Eloquent attribute and relation names. Override the protected accessor hooks
 * to remap without re-implementing the public surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsPrincipal
{
    /**
     * Return the principal's stable identifier (typically the model key).
     *
     * @return mixed
     */
    public function getPrincipalIdentifier(): mixed
    {
        return $this->getAttribute($this->getPrincipalIdentifierName());
    }

    /**
     * Return the identity that owns this principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    public function getIdentity(): Identity
    {
        // 2D mode: identity-is-principal, no `identity` relation.
        if ($this instanceof Identity) {

            return $this;
        }

        $identity = $this->getAttribute($this->getIdentityRelationName());

        if (!$identity instanceof Identity) {
            $message = sprintf(
                'Principal %s expected its identity relation `%s` to return an Identity instance, got %s.',
                static::class,
                $this->getIdentityRelationName(),
                get_debug_type($identity),
            );

            throw new \LogicException($message);
        }

        return $identity;
    }

    /**
     * Return the tenant the principal acts within, if any. Triggers a lazy-load
     * on first call; tenant-aware apps should eager-load via their principal
     * resolver.
     *
     * A model with no tenant relation, attribute, or loaded relation (the usual
     * 2D shape) acts within no tenant. It returns `null` without reading the
     * absent key, which Eloquent's strict mode would otherwise reject on every
     * authentication path that checks tenant activity. So does a relation that
     * returns a model which is not a `Tenant`.
     *
     * A tenant that opts into activation (its model implements both `Tenant`
     * and `CanBeActive`) is checked on every authentication path, so a
     * principal whose `BelongsTo` key names such a tenant that cannot be loaded
     * (deleted, soft-deleted, or hidden by a scope) throws rather than
     * returning `null`, which would read as acting within no tenant and skip
     * the tenant's activity check.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function getTenant(): ?Tenant
    {
        $name = $this->getTenantRelationName();

        if (!$this->hasAttribute($name) && !$this->isRelation($name) && !$this->relationLoaded($name)) {
            return null;
        }

        $tenant = $this->getAttribute($name);

        if ($tenant instanceof Tenant) {
            return $tenant;
        }

        if ($this->namesActivatableTenant($name)) {

            $message = sprintf(
                'Principal %s names a tenant through `%s` that cannot be loaded: it is deleted, soft-deleted, or hidden by a scope.',
                static::class,
                $name,
            );

            throw new TenantUnavailableException($message);
        }

        return null;
    }

    /**
     * Return the attribute name holding the principal identifier.
     *
     * @return string
     */
    protected function getPrincipalIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Return the relation name resolving to the owning identity.
     *
     * @return string
     */
    protected function getIdentityRelationName(): string
    {
        return 'identity';
    }

    /**
     * Return the relation name resolving to the acting tenant.
     *
     * @return string
     */
    protected function getTenantRelationName(): string
    {
        return 'tenant';
    }

    /**
     * Whether the tenant relation is a `BelongsTo` to a tenant that opts into
     * activation and its key is set, so the principal names a tenant whose
     * activity is checked, whether or not that tenant can be loaded.
     *
     * @param  string  $name
     * @return bool
     */
    private function namesActivatableTenant(string $name): bool
    {
        if (!$this->isRelation($name)) {
            return false;
        }

        $relation = $this->{$name}();

        return $relation instanceof BelongsTo
            && $relation->getRelated() instanceof Tenant
            && $relation->getRelated() instanceof CanBeActive
            && $this->getAttribute($relation->getForeignKeyName()) !== null;
    }
}
