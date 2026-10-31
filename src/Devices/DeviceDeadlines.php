<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Devices;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * The deadline rule every device's session follows: the session has ended from
 * the second its idle or absolute deadline names, and when it lacks either. The
 * guard's `TokenLifetimes` set the deadlines; this only reads them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeviceDeadlines
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether a device's session has ended at the given time: either deadline
     * is missing (the device has no session) or has been reached.
     *
     * The one deadline rule, shared by bearer requests, sign-in pins, refresh,
     * and token issuance.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     *
     * @throws \LogicException
     */
    public static function hasEnded(Device $device, CarbonInterface $now): bool
    {
        return self::liveDeadlines($device, $now) === null;
    }

    /**
     * Return a device's idle and absolute deadlines while its session is live
     * at the given time, or `null` once it has ended (see `hasEnded()`). Each
     * deadline is read once.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \Carbon\CarbonInterface  $now
     * @return array{0: \Carbon\CarbonInterface, 1: \Carbon\CarbonInterface}|null
     *
     * @throws \LogicException
     */
    public static function liveDeadlines(Device $device, CarbonInterface $now): ?array
    {
        $idle     = $device->getIdleExpiresAt();
        $absolute = $device->getAbsoluteExpiresAt();

        if ($idle === null || $absolute === null || $now->getTimestamp() >= min($idle->getTimestamp(), $absolute->getTimestamp())) {
            return null;
        }

        return [$idle, $absolute];
    }
}
