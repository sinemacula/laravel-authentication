<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * A connection named by a backed enum case.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubConnectionName: string
{
    case LANDLORD = 'landlord';
}
