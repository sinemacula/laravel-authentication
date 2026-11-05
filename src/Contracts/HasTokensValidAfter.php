<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Capability contract: an identity or principal that records from when its
 * access tokens issued without a session are valid.
 *
 * Optional supplement to `Identity` and `Principal`. A token that names a
 * session stops when the session is revoked; one issued without a session
 * (access only) has nothing to revoke, so signing out everywhere moves this
 * time forward instead, and the bearer path rejects every such token issued at
 * or before it. The time is read on the write connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasTokensValidAfter
{
    /**
     * Return the time at or before which access tokens issued without a session
     * are rejected, or `null` when there is none. A value that was not loaded
     * must not read as `null`: throw a `LogicException` instead.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getTokensValidAfter(): ?CarbonInterface;

    /**
     * Move the time forward to `$time`, never back, and persist it at once.
     * Returns whether it moved. A bulk revocation calls it only on a model
     * loaded from its row, a soft-deleted one among them, never on an Eloquent
     * model whose `exists` is `false` (hard-deleted, never saved, or built from
     * its key alone), so persisting through `save()` never inserts a row; such
     * a model's sessions end, but its cutoff stays where it is.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool;
}
