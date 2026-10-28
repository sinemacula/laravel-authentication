<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\DeviceKeyShape;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Finds a device someone named (a `did` claim, a device pinned on `attempt()`)
 * among an identity's own devices, and says whether a guard may authenticate on
 * it.
 *
 * Building the `devices()` relation, the lookup, and the guard, revocation and
 * deadline reads all run inside `WriteConnection::during()`, which pins every
 * connection a model resolves meanwhile: a relation that queries while it is
 * built (a list of permitted devices, say) and a device that derives its state
 * from a relation or another table read the writer as well.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OwnedDevice
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Find the device the hint names among the identity's devices, through its
     * `HasDevices` relation on the write connection. Returns `null`, without a
     * query, when the hint is `null`, the identity holds no devices, or the
     * hint cannot be a key of the device model, and when no such device of the
     * identity exists.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public static function find(Identity $identity, mixed $hint): ?Device
    {
        if ($hint === null || !$identity instanceof HasDevices) {
            return null;
        }

        return WriteConnection::during($identity, static function () use ($identity, $hint): ?Device {

            $devices = WriteConnection::query($identity->devices());

            if (!DeviceKeyShape::matches($devices->getModel(), $hint)) {
                return null;
            }

            $device = $devices->find($hint);

            return $device instanceof Device ? $device : null;
        });
    }

    /**
     * Why the guard may not authenticate on the device at the given time, or
     * `null` when it may: a device of another guard (or of none), a revoked
     * one, and one whose session has ended (past its idle or absolute deadline,
     * or without deadlines), in that order. The revocation and the deadlines
     * are read whatever the guard, so a device loaded without one of them is
     * reported as the misconfiguration it is. The deadlines are checked with no
     * leeway, so a token cannot outlive its session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $guard
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public static function refusal(Device $device, string $guard, CarbonInterface $now): ?FailureReason
    {
        return WriteConnection::during($device, static function () use ($device, $guard, $now): ?FailureReason {

            $revoked = $device->getRevokedAt() !== null;
            $ended   = TokenLifetimes::hasEnded($device, $now);

            return match (true) {
                $device->getGuard() !== $guard => FailureReason::DEVICE_GUARD_MISMATCH,
                $revoked                       => FailureReason::DEVICE_REVOKED,
                $ended                         => FailureReason::SESSION_EXPIRED,
                default                        => null,
            };
        });
    }
}
