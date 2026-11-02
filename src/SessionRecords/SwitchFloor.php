<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * Moves the floor a session sets for the issue time of its access tokens when
 * its context changes: a switch of principal or active tenant, a return to
 * pending, or an activation after one.
 *
 * Tokens carry their issue time to the second, so a floor of the change's own
 * second would still accept a token issued earlier in that second, which names
 * the same context again when the change comes back to it within the second (a
 * switch away and back, a return to pending and an activation). A change in a
 * second the floor already reaches therefore moves it one second past the
 * recorded one: no token from before a change is accepted after it, at the cost
 * of refusing the tokens the second change issues until the client refreshes
 * after that second.
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
