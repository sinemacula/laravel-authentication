<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched once for each scope a bulk revocation ended: every session of an
 * identity, or every session acting as a principal, signed out at once, by
 * `signOutEverywhere()`, `revokeSessions()`, `revokePrincipalSessions()`, or
 * the session service's security-change methods.
 *
 * Dispatched after the `SessionRevoked` of every session the call revoked, once
 * the revocation is committed on the session connection, and also when it
 * revoked none, so the action itself is recorded. `$tokensValidAfter` is the
 * cutoff the call moved the scope's "tokens valid after" to, ending its access
 * tokens issued without a session; `null` when the scope records no cutoff,
 * already had a later one, or was kept on purpose: `signOutEverywhere(true)`
 * from an access-only token, which names no session, leaves the identity's
 * cutoff where it is, since that token could only be ended through it. That
 * cutoff is written on the scope's own connection before the sessions are
 * revoked, so it stands even when the session transaction rolls back.
 *
 * The context's guard is the guard that acted; its identity is the identity
 * whose sessions ended (for a principal's scope, the principal's owner, read
 * afresh on the write connection, or `null` when it cannot be read); its
 * principal is the principal scope, or `null` for an identity's; its session is
 * the session kept signed in, if any, which never stands in for the principal.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedOutEverywhere implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  int  $revoked
     * @param  ?\Carbon\CarbonImmutable  $tokensValidAfter
     */
    public function __construct(

        /** Whose sessions ended, through which guard, and the session kept, if any. */
        public EventContext $context,

        /** Why the sessions were ended. */
        public RevocationReason $reason,

        /** How many sessions this call revoked. */
        public int $revoked,

        /** The cutoff this call set for the scope's access tokens issued without a session, if it set one. */
        public ?CarbonImmutable $tokensValidAfter,
    ) {}

    /**
     * Return whose sessions ended, through which guard, and the session kept.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
