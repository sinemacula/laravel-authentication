<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;

/**
 * The session service's lookups of one session, which `ActiveSessions` carries
 * out, as the listing does.
 *
 * They are delegations with no state of their own; they sit in a trait only so
 * the service stays within the number of methods one class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait LooksUpSessions
{
    /**
     * One of the identity's active sessions, of any guard, by its identifier,
     * for a "where you are signed in" detail or before revoking it: the same
     * summary the session list gives, without its digests, revocation or
     * principal, marked when it is the session this guard is authenticated with
     * for the request. Read on the write connection through the identity's
     * `sessions()` relation, so another identity's session is not found. `null`
     * when the session is not the identity's, is not active (pending, revoked,
     * or past a deadline) or does not exist, without saying which; an
     * identifier that cannot be a key of the session model is not queried.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $sessionId
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SessionSummary
     *
     * @throws \LogicException
     */
    public function session(Identity $identity, mixed $sessionId): ?SessionSummary
    {
        return ActiveSessions::find($identity, $sessionId, $this->binding->session());
    }
}
