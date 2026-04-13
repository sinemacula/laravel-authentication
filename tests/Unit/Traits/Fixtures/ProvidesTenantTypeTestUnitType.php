<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures;

/**
 * Fixture unit enum exercising the non-backed UnitEnum branch of the
 * ProvidesTenantType type resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ProvidesTenantTypeTestUnitType
{
    case STAFF;
    case CUSTOMER;
}
