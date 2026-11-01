<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Shipped session model on the `unreachable` connection, which a test points at
 * a database that cannot be opened, so every session lookup fails while
 * connecting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnreachableSession extends Session
{
    /** @var string|\UnitEnum|null The connection name for the model. */
    protected $connection = 'unreachable';
}
