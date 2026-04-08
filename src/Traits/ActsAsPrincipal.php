<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;

/**
 * Provides default Principal contract implementations sourced from
 * configurable Eloquent attribute and relation names. Override the
 * protected accessor hooks to remap without re-implementing the
 * public surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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
     * Return the organization the principal acts within, if any.
     * Triggers a lazy-load on first call; tenant-aware apps should
     * eager-load via their principal resolver.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Organization
     */
    public function getOrganization(): ?Organization
    {
        $organization = $this->getAttribute($this->getOrganizationRelationName());

        return $organization instanceof Organization ? $organization : null;
    }

    /**
     * Return whether the principal is currently active and may authenticate.
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return (bool) $this->getAttribute($this->getActiveAttributeName());
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
     * Return the relation name resolving to the acting organization.
     *
     * @return string
     */
    protected function getOrganizationRelationName(): string
    {
        return 'organization';
    }

    /**
     * Return the attribute name holding the active flag.
     *
     * @return string
     */
    protected function getActiveAttributeName(): string
    {
        return 'is_active';
    }
}
