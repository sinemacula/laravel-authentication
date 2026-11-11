<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * An identity or principal that records from when its access tokens issued
 * without a session are valid.
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
     * are rejected, or `null` for none.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getTokensValidAfter(): ?CarbonInterface;

    /**
     * Move the time forward to `$time`, never back, and persist it at once;
     * returns whether it moved.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool;
}
