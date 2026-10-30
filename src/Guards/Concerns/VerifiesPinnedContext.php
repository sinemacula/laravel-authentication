<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Devices\IdentityDevices;
use SineMacula\Laravel\Authentication\Devices\OwnedDevice;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;

/**
 * Proves that a principal or device pinned on `attempt()` belongs to the
 * identity signing in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait VerifiesPinnedContext
{
    /**
     * Resolve a caller-supplied principal through the resolver's hinted path,
     * with the exact-match and ownership checks of
     * `PinnedPrincipal::resolve()`, and return the resolver's instance. Returns
     * `null` when the identity does not own a principal of the same class with
     * that identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    protected function resolvePinnedPrincipal(Identity $identity, Principal $pinned): ?Principal
    {
        return PinnedPrincipal::resolve($this->resolver, $identity, $pinned);
    }

    /**
     * Look a caller-supplied device up among the identity's own devices and
     * return the live row, when its session acts as the principal being bound.
     * Returns `null` when the identity owns no live device of the same class
     * with that identifier (see `resolveDeviceFromHint()`), or the device
     * records another principal, or none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \LogicException
     */
    protected function resolvePinnedDevice(Identity $identity, Principal $principal, Device $pinned): ?Device
    {
        $owned = $this->resolveDeviceFromHint($identity, $pinned->getDeviceIdentifier());

        return $owned !== null && $owned::class === $pinned::class && OwnedDevice::actsAs($owned, $principal) ? $owned : null;
    }

    /**
     * Resolve a device for the identity from a pinned device's identifier.
     * Returns null when the identity does not implement `HasDevices`, the hint
     * cannot be a key of the device model (no query is made), or the device is
     * not found (`IdentityDevices::find()`), belongs to another guard's
     * sessions (or to none), has been revoked, or its session has ended (past
     * its idle or absolute deadline, or without deadlines): such a device is
     * treated exactly like a missing one, from the row already loaded, on the
     * write connection (see `OwnedDevice`). The deadlines are checked against
     * the current time with no leeway, so a pin cannot outlive its session. A
     * `devices()` relation over a model that is not an `EloquentDevice` is a
     * misconfiguration, and throws.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \LogicException
     */
    protected function resolveDeviceFromHint(Identity $identity, mixed $hint): ?Device
    {
        $device = IdentityDevices::find($identity, $hint);

        return $device !== null && OwnedDevice::refusal($device, $this->name, Carbon::now()) === null ? $device : null;
    }
}
