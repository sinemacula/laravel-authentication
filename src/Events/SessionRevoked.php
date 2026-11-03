<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched when the package revokes a session, ending it everywhere at once:
 * a sign-out (`signOut()`, `logout()`), a revocation the application asks the
 * session service for (`revokeSession()`, `revokeSessions()`,
 * `revokePrincipalSessions()`, `signOutEverywhere()` and the security-change
 * methods), a refresh or switch that caught a replayed refresh token, and a
 * sign-in that replaced the session the client proved it holds (`superseded`,
 * just before that sign-in's `SessionCreated`). A session an application
 * revokes by writing `revoked_at` itself is not reported.
 *
 * Fired only by the call that revoked the session, not for one that was already
 * revoked, and only once the revocation is committed on the session's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a revocation that is rolled
 * back. A transaction on another connection neither delays nor cancels it.
 *
 * The context's guard is the session's own and its session is never `null`. The
 * identity, principal and tenant are those the revoking flow holds; the
 * snapshot of an identity or principal it does not hold is the owner or
 * principal the session row records (a replay is caught before the owner is
 * loaded, so its models are `null` and its snapshots name what the row
 * records). The tenant is carried only by `signOut()`, `tenantDeactivated()`
 * and a sign-in's replacement (the tenant it admitted), since sessions record
 * none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionRevoked implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     */
    public function __construct(

        /** The revoked session, its guard, and whose it was as far as known. */
        public EventContext $context,

        /** Why the session was revoked. */
        public RevocationReason $reason,
    ) {}

    /**
     * Return the revoked session and whose it was.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
