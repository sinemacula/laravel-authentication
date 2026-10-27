<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\DeviceKeyShape;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Proves that a principal or device someone else named belongs to an identity:
 * a principal hint (a `pid` claim or a principal pinned on `attempt()`) and a
 * device hint (a `did` claim or a device pinned on `attempt()`).
 *
 * Expects the using class to declare:
 * - `protected function resolvePrincipal(Identity $identity, mixed $hint =
 *   null): ?Principal`
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
     * with the exact-match check the bearer path applies to a `pid` claim, and
     * return the resolver's instance. Returns `null` when the identity does not
     * own a principal of the same class with that identifier.
     *
     * Ownership is checked here as well, rather than trusted to the resolver:
     * the resolved principal's own identity must be the authenticated one, so a
     * resolver whose hinted lookup is not scoped to the identity cannot bind
     * another identity's principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    protected function resolvePinnedPrincipal(Identity $identity, Principal $pinned): ?Principal
    {
        $hint     = $pinned->getPrincipalIdentifier();
        $resolved = $this->resolvePrincipal($identity, $hint);

        if ($resolved === null || $resolved::class !== $pinned::class || !$this->matchesPidHint($resolved, $hint)) {
            return null;
        }

        return $this->isOwnedBy($resolved, $identity) ? $resolved : null;
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
     * device's identifier), reading from the write connection so a lagging
     * replica cannot resolve a deleted or revoked device. Returns null when the
     * identity does not implement `HasDevices`, the hint cannot be a key of the
     * device model (no query is made), or the device is not found or has been
     * revoked: a revoked device is treated exactly like a missing one, from the
     * row already loaded.
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

        $devices = WriteConnection::query($identity->devices());

        if (!DeviceKeyShape::matches($devices->getModel(), $hint)) {
            return null;
        }

        $device = $devices->find($hint);

        return $device instanceof Device && $device->getRevokedAt() === null ? $device : null;
    }

    /**
     * Whether the principal's owning identity is the given identity: the same
     * class with the same auth identifier. The owner is read with reads on the
     * principal's connection pinned to the write connection. In 2D mode the
     * principal is its own identity.
     *
     * An Eloquent principal's owner is read from its own stored key on a copy
     * without loaded relations, so an identity relation the resolver already
     * set (for example the inverse of the lookup it made) cannot vouch for the
     * principal. A principal whose owner cannot be read (`getIdentity()` throws
     * a `LogicException`, as `ActsAsPrincipal` does for a deleted owner or a
     * model without an identity relation) is not owned, so the pin fails the
     * attempt rather than the request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    private function isOwnedBy(Principal $principal, Identity $identity): bool
    {
        $stored = $principal instanceof Model ? $principal->withoutRelations() : $principal;

        try {
            $owner = WriteConnection::during($stored, static fn (): Identity => $stored->getIdentity());
        } catch (\LogicException) {
            return false;
        }

        return $owner::class === $identity::class
            && IdentifierCoercion::matches($owner->getAuthIdentifier(), $identity->getAuthIdentifier());
    }
}
