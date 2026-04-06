<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Principal contract.
 *
 * Describes the *acting* entity for an authenticated request,
 * which may differ from the underlying identity (in the 3D model)
 * or be the identity itself (in the 2D model).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface Principal
{
    /** Return the principal's stable identifier (typically the model key). */
    public function getPrincipalIdentifier(): mixed;

    /** Return the identity that owns this principal (in 2D mode this is the principal itself). */
    public function getIdentity(): Identity;

    /** Return the organization the principal acts within, if any. */
    public function getOrganization(): ?Organization;

    /** Return whether the principal is currently active and may authenticate. */
    public function isActive(): bool;
}
