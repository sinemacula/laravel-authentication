<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits\Fixtures;

/**
 * Fixture backed enum exercising the BackedEnum branch of the
 * ActsAsOrganization scope resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
enum ActsAsOrganizationTestBackedScope: string
{
    case Internal = 'internal';
    case External = 'external';
}
