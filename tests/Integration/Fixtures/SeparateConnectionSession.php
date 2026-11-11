<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Shipped session model on its own `session_store` connection, outside any
 * transaction on the default one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeparateConnectionSession extends Session
{
    /** @var string The connection the session's table lives on. */
    public const string CONNECTION = 'session_store';

    /** @var string|\UnitEnum|null The connection name for the model. */
    protected $connection = self::CONNECTION;
}
