<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Proves that a principal or device someone else named belongs to an identity:
 * a principal hint (a `pid` claim or a principal pinned on `attempt()`) and a
 * device pinned on `attempt()`.
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
        if ($resolved === null) {
            return false;
        }

        $resolvedId = IdentifierCoercion::stringify($resolved->getPrincipalIdentifier());
        $hintId     = IdentifierCoercion::stringify($hint);

        return $resolvedId !== null && $hintId !== null && hash_equals($resolvedId, $hintId);
    }

    /**
     * Resolve a caller-supplied principal through the resolver's hinted path,
     * with the exact-match check the bearer path applies to a `pid` claim, and
     * return the resolver's instance. Returns `null` when the identity does not
     * own a principal of the same class with that identifier.
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

        return $resolved !== null && $resolved::class === $pinned::class && $this->matchesPidHint($resolved, $hint)
            ? $resolved
            : null;
    }

    /**
     * Look a caller-supplied device up among the identity's own devices and
     * return the live row. Returns `null` when the identity cannot own devices,
     * owns no device of the same class with that identifier, or the device is
     * revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function resolvePinnedDevice(Identity $identity, Device $pinned): ?Device
    {
        $identifier = $pinned->getDeviceIdentifier();

        if ($identifier === null || !$identity instanceof HasDevices) {
            return null;
        }

        $owned = $identity->devices()->find($identifier);

        return $owned instanceof Device && $owned::class === $pinned::class && $owned->getRevokedAt() === null
            ? $owned
            : null;
    }
}
