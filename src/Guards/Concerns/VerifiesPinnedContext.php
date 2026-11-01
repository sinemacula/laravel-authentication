<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;

/**
 * Proves that a principal or session pinned on `attempt()` belongs to the
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
        return PinnedPrincipal::resolve($this->context->resolver(), $identity, $pinned);
    }

    /**
     * Look a caller-supplied session up among the identity's own sessions and
     * return the live row, when it acts as the principal being bound. Returns
     * `null` when the identity owns no live session of the same class with that
     * identifier (see `resolveSessionFromHint()`), or the session records
     * another principal, or none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \LogicException
     */
    protected function resolvePinnedSession(Identity $identity, Principal $principal, Session $pinned): ?Session
    {
        $owned = $this->resolveSessionFromHint($identity, $pinned->getSessionIdentifier());

        return $owned !== null && $owned::class === $pinned::class && OwnedSession::actsAs($owned, $principal) ? $owned : null;
    }

    /**
     * Resolve a session for the identity from a pinned session's identifier.
     * Returns null when the identity does not implement `HasSessions`, the hint
     * cannot be a key of the session model (no query is made), or the session
     * is not found (`IdentitySessions::find()`), belongs to another guard's
     * sessions (or to none), has been revoked, or has ended (past its idle or
     * absolute deadline, or without deadlines): such a session is treated
     * exactly like a missing one, from the row already loaded, on the write
     * connection (see `OwnedSession`). The deadlines are checked against the
     * current time with no leeway, so a pin cannot outlive its session. A
     * `sessions()` relation over a model that is not an `EloquentSession` is a
     * misconfiguration, and throws.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \LogicException
     */
    protected function resolveSessionFromHint(Identity $identity, mixed $hint): ?Session
    {
        $session = IdentitySessions::find($identity, $hint);

        return $session !== null && OwnedSession::refusal($session, $this->context->name(), Carbon::now()) === null ? $session : null;
    }
}
