<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Jwt\DeviceKeyShape;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Proves that a principal or device someone else named belongs to an identity:
 * a principal hint (a `pid` claim or a principal pinned on `attempt()`) and a
 * device hint (a `did` claim or a device pinned on `attempt()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait VerifiesPinnedContext
{
    /**
     * Confirm a resolver-returned principal matches a principal hint (a `pid`
     * claim or a caller-supplied principal's identifier), so a hint that
     * resolves to a different principal is rejected rather than silently
     * downgraded.
     *
     * Fail-closed on unsaved principals: if either identifier stringifies to
     * `null` (an unsaved model returned by a misbehaving custom resolver), the
     * match returns `false` so the guard does not bind a transient actor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $resolved
     * @param  mixed  $hint
     * @return bool
     */
    protected function matchesPidHint(?Principal $resolved, mixed $hint): bool
    {
        return IdentifierCoercion::matches($resolved?->getPrincipalIdentifier(), $hint);
    }

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
     * return the live row. Returns `null` when the identity owns no live device
     * of the same class with that identifier (see `resolveDeviceFromHint()`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function resolvePinnedDevice(Identity $identity, Device $pinned): ?Device
    {
        $owned = $this->resolveDeviceFromHint($identity, $pinned->getDeviceIdentifier());

        return $owned !== null && $owned::class === $pinned::class ? $owned : null;
    }

    /**
     * Resolve a device for the identity from a hint (a `did` claim or a pinned
     * device's identifier). Returns null when the identity does not implement
     * `HasDevices`, the hint cannot be a key of the device model (no query is
     * made), or the device is not found, has been revoked, or its session has
     * ended (past its idle or absolute deadline, or without deadlines): a
     * revoked or ended device is treated exactly like a missing one, from the
     * row already loaded. The deadlines are checked against the current time
     * with no leeway, so a token cannot outlive its session.
     *
     * Building the `devices()` relation, the lookup, and the revocation and
     * deadline reads all run inside `WriteConnection::during()` for the
     * identity, which pins every connection a model resolves meanwhile: a
     * relation that queries while it is built (a list of permitted devices,
     * say) and a device that derives its state from a relation or another table
     * read the writer as well.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function resolveDeviceFromHint(Identity $identity, mixed $hint): ?Device
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

            return $device instanceof Device && $device->getRevokedAt() === null && !TokenLifetimes::hasEnded($device, Carbon::now()) ? $device : null;
        });
    }
}
