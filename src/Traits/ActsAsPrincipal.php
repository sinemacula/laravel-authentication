<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Traits;

use LogicException;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;

/**
 * Provides default Principal contract method implementations sourced
 * from configurable Eloquent model attribute and relation names.
 *
 * Consumers may override the protected accessor hooks below to map
 * the contract onto non-default columns or relations without
 * re-implementing the public surface.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
trait ActsAsPrincipal
{
    /** Return the principal's stable identifier (typically the model key). */
    public function getPrincipalIdentifier(): mixed
    {
        return $this->getAttribute($this->getPrincipalIdentifierName());
    }

    /**
     * Return the identity that owns this principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException When the identity relation is absent or not an Identity instance.
     */
    public function getIdentity(): Identity
    {
        // 2D mode: when the consuming model implements both Identity
        // and Principal, the principal IS the identity. Return $this
        // directly rather than attempting to resolve a separate
        // `identity` relation that does not exist in 2D mode.
        if ($this instanceof Identity) {

            return $this;
        }

        $identity = $this->getAttribute($this->getIdentityRelationName());

        if (! $identity instanceof Identity) {
            throw new LogicException(sprintf(
                'Principal %s expected its identity relation `%s` to return an Identity instance, got %s.',
                static::class,
                $this->getIdentityRelationName(),
                get_debug_type($identity),
            ));
        }

        return $identity;
    }

    /** Return the organization the principal acts within, if any. */
    public function getOrganization(): ?Organization
    {
        $organization = $this->getAttribute($this->getOrganizationRelationName());

        return $organization instanceof Organization ? $organization : null;
    }

    /** Return whether the principal is currently active and may authenticate. */
    public function isActive(): bool
    {
        return (bool) $this->getAttribute($this->getActiveAttributeName());
    }

    /** Return the attribute name holding the principal identifier. */
    protected function getPrincipalIdentifierName(): string
    {
        return 'id';
    }

    /** Return the relation name resolving to the owning identity. */
    protected function getIdentityRelationName(): string
    {
        return 'identity';
    }

    /** Return the relation name resolving to the acting organization. */
    protected function getOrganizationRelationName(): string
    {
        return 'organization';
    }

    /** Return the attribute name holding the active flag. */
    protected function getActiveAttributeName(): string
    {
        return 'is_active';
    }
}
