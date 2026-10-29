<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures\Enums;

/**
 * Fixture unit enum exercising the non-backed UnitEnum branch of the
 * ProvidesType type resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ProvidesTypeTestUnitType
{
    case STAFF;
    case CUSTOMER;
}
