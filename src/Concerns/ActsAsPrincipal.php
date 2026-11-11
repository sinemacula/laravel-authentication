<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * Default `Principal` implementations read from configurable Eloquent attribute
 * and relation names.
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
     * The name is checked first, as Eloquent's strict mode rejects absent keys.
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

        $name     = $this->getIdentityRelationName();
        $identity = $this->hasAttribute($name) || $this->isRelation($name) || $this->relationLoaded($name)
            ? $this->getAttribute($name)
            : null;

        if (!$identity instanceof Identity) {
            $message = sprintf(
                'Principal %s expected its identity relation `%s` to return an Identity instance, got %s.',
                static::class,
                $name,
                get_debug_type($identity),
            );

            throw new \LogicException($message);
        }

        return $identity;
    }

    /**
     * Return the tenant the principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    public function getTenant(): ?Tenant
    {
        $name = $this->getTenantRelationName();

        if (!$this->hasAttribute($name) && !$this->isRelation($name) && !$this->relationLoaded($name)) {
            return null;
        }

        if (!$this->relationLoaded($name)) {
            $this->activatableTenantRelation($name);
        }

        $tenant = $this->getAttribute($name);

        if ($tenant instanceof Tenant && !$this->isActivatableTenantPlaceholder($tenant, $name)) {
            return $tenant;
        }

        $this->assertNamesNoUnloadedTenant($name);

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
     * Throw when the principal, having loaded no tenant, names a tenant that
     * opts into activation.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    private function assertNamesNoUnloadedTenant(string $name): void
    {
        $relation = $this->activatableTenantRelation($name);

        if ($relation === null) {
            return;
        }

        $key = $relation->getForeignKeyName();

        if (!array_key_exists($key, $this->getAttributes())) {
            throw new \LogicException($this->unloadedTenantAttributeMessage($key));
        }

        if ($this->getAttribute($key) === null) {
            return;
        }

        $message = sprintf(
            'Principal %s names a tenant through `%s` that cannot be loaded: it is deleted, soft-deleted, or hidden by a scope.',
            static::class,
            $name,
        );

        throw new TenantUnavailableException($message, $relation->getRelated()::class, $relation->getOwnerKeyName(), $this->getAttribute($key));
    }

    /**
     * Whether the tenant is an unsaved `withDefault()` placeholder for a tenant
     * that opts into activation.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $name
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    private function isActivatableTenantPlaceholder(Tenant $tenant, string $name): bool
    {
        return $tenant instanceof Model && !$tenant->exists && $this->activatableTenantRelation($name) !== null;
    }

    /**
     * Return the tenant relation when it is a `BelongsTo` to a tenant that opts
     * into activation.
     *
     * @formatter:off
     *
     * @param  string  $name
     * @return ?\Illuminate\Database\Eloquent\Relations\BelongsTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    private function activatableTenantRelation(string $name): ?BelongsTo
    {
        if (!$this->isRelation($name)) {
            return null;
        }

        $relation = $this->{$name}();

        if ($relation instanceof MorphTo) {
            $this->assertNamesTenantType($relation, $name);
        }

        return $relation instanceof BelongsTo
            && $relation->getRelated() instanceof Tenant
            && $relation->getRelated() instanceof CanBeActive ? $relation : null;
    }

    /**
     * Throw when a polymorphic tenant relation cannot say which model it names.
     *
     * Eloquent builds a typeless relation against the principal's own model.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>  $relation
     * @param  string  $name
     * @return void
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    private function assertNamesTenantType(MorphTo $relation, string $name): void
    {
        $attributes = $this->getAttributes();
        $type       = $relation->getMorphType();

        if (!array_key_exists($type, $attributes)) {
            throw new \LogicException($this->unloadedTenantAttributeMessage($type));
        }

        if ($attributes[$type] !== null && $attributes[$type] !== '') {
            return;
        }

        $key = $relation->getForeignKeyName();

        if (!array_key_exists($key, $attributes)) {
            throw new \LogicException($this->unloadedTenantAttributeMessage($key));
        }

        if ($this->getAttribute($key) === null) {
            return;
        }

        $message = sprintf(
            'Principal %s names a tenant through `%s` without its `%s` type, so it cannot be loaded.',
            static::class,
            $name,
            $type,
        );

        throw new TenantUnavailableException($message);
    }

    /**
     * Build the message reporting a tenant attribute the principal was loaded
     * without.
     *
     * @param  string  $attribute
     * @return string
     */
    private function unloadedTenantAttributeMessage(string $attribute): string
    {
        return sprintf(
            'Cannot determine the tenant %s acts within: its `%s` attribute is not loaded.'
            . ' Select the column so the tenant can be checked.',
            static::class,
            $attribute,
        );
    }
}
