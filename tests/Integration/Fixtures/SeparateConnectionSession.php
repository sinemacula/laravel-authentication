<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * The shipped session model kept on its own connection, `session_store`, apart
 * from the identities and from any transaction the application opens on the
 * default connection.
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
