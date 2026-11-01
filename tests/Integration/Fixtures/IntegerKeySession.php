<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * The shipped session model keyed by an integer the database issues rather than
 * a UUID it generates, so a key is issued again once the table's counter is
 * reset, as truncating the table resets it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerKeySession extends Session
{
    /**
     * No column receives a generated unique identifier: the database issues the
     * key.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return [];
    }
}
