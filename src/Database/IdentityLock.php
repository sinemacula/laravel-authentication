<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Eloquent\Model;

/**
 * Locks an identity's row before the proofs bound to it, the lock order of
 * every transaction that writes both.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityLock
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Lock the identity's row until the transaction around the call ends, and
     * return it as stored, or `null` when it is no longer stored.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $identity
     * @return ?TModel
     *
     * @imperative
     */
    public static function acquire(Model $identity): ?Model
    {
        return $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->first();
    }
}
