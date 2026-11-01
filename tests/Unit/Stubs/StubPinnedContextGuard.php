<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
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
     * Expose `resolveSessionFromHint()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     */
    public function sessionFromHint(Identity $identity, mixed $hint): ?Session
    {
        return $this->resolveSessionFromHint($identity, $hint);
    }

    /**
     * Expose `resolvePinnedSession()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     */
    public function pinnedSession(Identity $identity, Principal $principal, Session $pinned): ?Session
    {
        return $this->resolvePinnedSession($identity, $principal, $pinned);
    }
}
