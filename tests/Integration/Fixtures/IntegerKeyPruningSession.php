<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Shipped session model with an auto-incrementing integer key, which proofs and
 * provenance record as a string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerKeyPruningSession extends Session
{
    /**
     * No column receives a generated unique identifier: the database numbers
     * the key.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return [];
    }
}
