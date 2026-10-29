<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Capability contract: an identity or principal that records from when its
 * access tokens issued without a device are valid.
 *
 * Optional supplement to `Identity` and `Principal`. A token that names a
 * device stops when its device is revoked; one issued without a device (access
 * only) has nothing to revoke, so signing out everywhere moves this time
 * forward instead, and the bearer path rejects every such token issued at or
 * before it. The time is read on the write connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasTokensValidAfter
{
    /**
     * Return the time at or before which access tokens issued without a device
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
     * Returns whether it moved.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool;
}
