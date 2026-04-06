<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Organization contract.
 *
 * Describes a tenant scope a principal acts within in the 3D model.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface Organization
{
    /** Return the organization's stable identifier (typically the model key). */
    public function getOrganizationIdentifier(): mixed;

    /** Return the organization's scope string (e.g. internal/external/customer). */
    public function getOrganizationScope(): string;
}
