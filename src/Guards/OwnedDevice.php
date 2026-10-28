<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * Says whether a guard may authenticate on a device someone named (a `did`
 * claim, a device pinned on `attempt()`), once `IdentityDevices::find()` has
 * found it among the identity's own devices.
 *
 * The guard, revocation and deadline reads run inside
 * `WriteConnection::during()`, which pins every connection a model resolves
 * meanwhile, so a device that derives its state from a relation or another
 * table reads the writer as well.
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

    /**
     * Whether the device's session acts as the principal: the device records
     * that principal's type and identifier, read from the row already loaded,
     * with no query. A device that records no principal, or that is not an
     * Eloquent device able to record one, acts as none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function actsAs(Device $device, Principal $principal): bool
    {
        return $device instanceof EloquentDevice && $device instanceof Model && PrincipalReference::isRecordedOn($device, $principal);
    }

    /**
     * Whether a token issued at the given time (its `iat`) was issued at or
     * after the session last switched its principal, so a token of a principal
     * the session switched away from cannot come back to life when it switches
     * back. A session that never switched accepts any time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  mixed  $issuedAt
     * @return bool
     *
     * @throws \LogicException
     */
    public static function isIssuedSinceSwitch(Device $device, mixed $issuedAt): bool
    {
        $switched = WriteConnection::during($device, static fn (): ?CarbonInterface => $device->getPrincipalSwitchedAt());

        return $switched === null || (is_int($issuedAt) && $issuedAt >= $switched->getTimestamp());
    }
}
