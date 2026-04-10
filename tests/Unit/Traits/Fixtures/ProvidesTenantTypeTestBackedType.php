<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures;

/**
 * Fixture backed enum exercising the BackedEnum branch of the
 * ProvidesTenantType type resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
enum ProvidesTenantTypeTestBackedType: string
{
    case STAFF    = 'staff';
    case CUSTOMER = 'customer';
}
