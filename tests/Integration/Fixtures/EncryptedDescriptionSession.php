<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Session model that encrypts the client name and platform it records, so what
 * it stores differs from what it reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EncryptedDescriptionSession extends Session
{
    /**
     * The attributes that should be cast: the shipped casts, with both
     * descriptions encrypted.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            ...parent::casts(),
            'client_name' => 'encrypted',
            'platform'    => 'encrypted',
        ];
    }
}
