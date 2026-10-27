<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures\Enums;

/**
 * Fixture backed enum exercising the BackedEnum branch of the ProvidesType type
 * resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ProvidesTypeTestBackedType: string
{
    case STAFF    = 'staff';
    case CUSTOMER = 'customer';
}
