<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shipped device model on the `unreachable` connection, which a test points at
 * a database that cannot be opened, so every device lookup fails while
 * connecting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnreachableDevice extends Device
{
    /** @var string|\UnitEnum|null The connection name for the model. */
    protected $connection = 'unreachable';
}
