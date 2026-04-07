<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures;

/**
 * Fixture unit enum exercising the non-backed UnitEnum branch of the
 * ActsAsOrganization scope resolver.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
enum ActsAsOrganizationTestUnitScope
{
    case Internal;
    case External;
}
