<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\ValidatesSessionKey;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Shipped session model keyed by `session.<uuid>` strings, a format it
 * describes through `ValidatesSessionKey`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DottedKeySession extends Session implements ValidatesSessionKey
{
    /**
     * A new key: `session.` and a UUID.
     *
     * @return string
     */
    #[\Override]
    public function newUniqueId(): string
    {
        return 'session.' . Str::uuid7();
    }

    /**
     * Whether the value is a `session.` key.
     *
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function isValidSessionKey(mixed $key): bool
    {
        return is_string($key) && preg_match('/^session\.[0-9a-f-]{36}$/', $key) === 1;
    }
}
