<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Lets a session model whose key is not an integer, UUID or ULID say whether a
 * token's `sid` has the key's shape before it is queried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ValidatesSessionKey
{
    /**
     * Whether the value has the shape of this model's primary key.
     *
     * @param  mixed  $key
     * @return bool
     */
    public function isValidSessionKey(mixed $key): bool;
}
