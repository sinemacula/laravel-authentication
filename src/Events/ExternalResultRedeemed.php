<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;

/**
 * Dispatched when a result an external identity provider verified was redeemed:
 * an adapter's `signInExternally()` wrote its session, active or pending
 * (`sign_in`), or its `reauthenticateExternally()` issued the session a new
 * access token (`reauthentication`).
 *
 * Dispatched once the redemption commits on the session's own connection, after
 * the events that report the session itself (`SessionCreated` and `SignedIn`,
 * `SessionPending`, or `Reauthenticated`), and never for a redemption that is
 * rolled back. A refused redemption dispatches `AuthenticationFailed` instead.
 *
 * The context carries the guard, the client, the identity, the principal and
 * the tenant as far as the redemption established them (a pending sign-in
 * waiting on a choice names no principal), the session, the method
 * `external_provider`, and the connection and the authorisation request's
 * public reference (`connectionId`, `requestReference`, when the result had
 * one), so a listener correlates it with the provider-side completion that
 * reported the same reference. The session's own events do not carry them;
 * they correlate with this one by the session's identifier.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResultRedeemed extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     */
    public function __construct(

        // Who the result was redeemed for, into which session, through which
        // connection and for which request.
        EventContext $context,

        /** What the result was redeemed for: `sign_in` or `reauthentication`. */
        public AuthenticationFlow $flow,
    ) {
        parent::__construct($context);
    }
}
