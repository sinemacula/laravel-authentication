<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

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
     * authentication path that checks tenant activity.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function getTenant(): ?Tenant
    {
        $name = $this->getTenantRelationName();

        if (!$this->hasAttribute($name) && !$this->isRelation($name) && !$this->relationLoaded($name)) {
            return null;
        }

        $tenant = $this->getAttribute($name);

        return $tenant instanceof Tenant ? $tenant : null;
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
}
