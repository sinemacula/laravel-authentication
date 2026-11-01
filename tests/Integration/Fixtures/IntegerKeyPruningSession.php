<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * The shipped session model with an auto-incrementing integer key instead of
 * its UUID, so pruning its sessions must find their proofs and provenance by
 * the key as a string, the form the proofs record it in, rather than by
 * comparing an integer column with a string one. Its table is the configured
 * session table, as the shipped model's is.
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
