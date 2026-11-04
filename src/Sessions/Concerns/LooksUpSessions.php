<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;

/**
 * The session service's lookups of one session and of one principal, which
 * `ActiveSessions` and `PendingEvaluation` carry out, as the session list and
 * `principals()` do.
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

    /**
     * One of the principals the identity may use the application as, by its
     * principal identifier, for a switch destination or a "your memberships"
     * detail: the one `principals()` would list with that identifier, judged by
     * the same reads and checks (the identity's `principals()` on the write
     * connection, or the resolver's default, each active, in an active tenant
     * or none, and allowed to use the application by `ApplicationAccess`), and
     * with an identifier type the application policy must admit the identity
     * with it first. `null` when the principal is not the identity's, is not
     * admitted, or two of the identity's principals share the identifier,
     * without saying which. A switch destination is checked again by the
     * switch. A principal found that uses `ActsAsPrincipal` holds its tenant,
     * loaded on the write connection, so reading `getTenant()` on it costs no
     * further query and never lazy-loads, even under Eloquent strict mode.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $principalId
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(Identity $identity, mixed $principalId, ?string $identifierType = null): ?Principal
    {
        return $this->evaluation->principal($identity, $principalId, $identifierType);
    }
}
