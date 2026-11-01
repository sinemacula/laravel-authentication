<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\ValidatesSessionKey;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * The shipped session model keyed by free-form strings as long as the
 * identifier columns hold, 255 characters, most of them taking two bytes, so a
 * length counted in bytes would take the key for one longer than any column
 * holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WideKeySession extends Session implements ValidatesSessionKey
{
    /**
     * A new key: 219 two-byte characters and a UUID, 255 characters in all.
     *
     * @return string
     */
    #[\Override]
    public function newUniqueId(): string
    {
        return str_repeat('é', 219) . Str::uuid7();
    }

    /**
     * Whether the value is a key: any string that is not empty.
     *
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function isValidSessionKey(mixed $key): bool
    {
        return is_string($key) && $key !== '';
    }
}
