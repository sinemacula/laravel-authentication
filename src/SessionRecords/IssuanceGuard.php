<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * The write to the session row's issuance sequence that serialises token
 * issuance against changes to the session's proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IssuanceGuard
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Increment the session's issuance sequence, returning whether the row
     * still exists.
     *
     * The query builder keeps model events and `updated_at` out of it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public static function write(EloquentSession&Model $session): bool
    {
        $key = $session->getKey() ?? throw new \LogicException('The issuance guard can only be written for a session that has a key.');

        return $session->getConnection()
            ->table($session->getTable())
            ->where($session->getKeyName(), $key)
            ->increment($session->getIssuanceSequenceName()) === 1;
    }

    /**
     * Write the guard of a session whose row must exist.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public static function hold(EloquentSession&Model $session): void
    {
        self::write($session) || throw new \LogicException('The session\'s row no longer exists, so its issuance guard cannot be written.');
    }
}
