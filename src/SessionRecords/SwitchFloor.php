<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * Moves the floor a session sets for the issue time of its access tokens when
 * its context changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SwitchFloor
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The floor a context change at `$now` sets: `$now` when the session
     * records none or an earlier one, else one second past the recorded floor.
     *
     * @param  ?\Carbon\CarbonInterface  $recorded
     * @param  \Carbon\CarbonImmutable  $now
     * @return \Carbon\CarbonImmutable
     */
    public static function after(?CarbonInterface $recorded, CarbonImmutable $now): CarbonImmutable
    {
        $now = $now->startOfSecond();

        return $recorded === null || $recorded->getTimestamp() < $now->getTimestamp()
            ? $now
            : CarbonImmutable::createFromTimestamp($recorded->getTimestamp() + 1, $now->getTimezone());
    }
}
