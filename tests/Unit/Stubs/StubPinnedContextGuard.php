<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Guard test double exposing the `VerifiesPinnedContext` checks to a subclass
 * caller, as `JwtGuard` uses them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubPinnedContextGuard extends AbstractGuard
{
    /**
     * Expose `matchesPidHint()`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $resolved
     * @param  mixed  $hint
     * @return bool
     */
    public function matches(?Principal $resolved, mixed $hint): bool
    {
        return $this->matchesPidHint($resolved, $hint);
    }

    /**
     * Expose `resolvePinnedPrincipal()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function pinnedPrincipal(Identity $identity, Principal $pinned): ?Principal
    {
        return $this->resolvePinnedPrincipal($identity, $pinned);
    }

    /**
     * Expose `resolveDeviceFromHint()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public function deviceFromHint(Identity $identity, mixed $hint): ?Device
    {
        return $this->resolveDeviceFromHint($identity, $hint);
    }

    /**
     * Expose `resolvePinnedDevice()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public function pinnedDevice(Identity $identity, Principal $principal, Device $pinned): ?Device
    {
        return $this->resolvePinnedDevice($identity, $principal, $pinned);
    }
}
