<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched for every real sign-in: when the session service starts a new
 * session, with the method that proved who signed in, and when a refresh renews
 * one (`refresh` set, after `Refreshed`), with the method the session records.
 * A bearer request, which only authenticates, never dispatches it. `attempt()`
 * starts no session and never dispatches it; Laravel's `Login` reports its
 * sign-ins.
 *
 * Dispatched once the session is committed on the session's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a sign-in that is rolled back. A sign-in
 * that starts a session follows its `SessionCreated`, and the `SessionRevoked`
 * (`superseded`) of the session it replaced, if any; a refresh has neither.
 *
 * The context carries the guard, the client the sign-in came from, the
 * identity, principal, tenant and session, and the method. Never carries a
 * credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedIn extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  bool  $refresh
     */
    public function __construct(

        // Who signed in, as which principal, in which session, how, and from
        // which client.
        EventContext $context,

        /** Whether a refresh renewed the session, rather than a sign-in starting it. */
        public bool $refresh,
    ) {
        parent::__construct($context);
    }
}
