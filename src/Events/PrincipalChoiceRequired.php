<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;

/**
 * Dispatched when the session service holds a sign-in for the identity to
 * choose the principal its session acts as, because none was named, the
 * resolver has no default, and the identity has principals it may sign in as.
 * Choosing one (`choose()`) continues the sign-in; discarding the choice
 * dispatches `AuthenticationFailed` with `principal_choice_abandoned`.
 *
 * Dispatched once the pending choice is committed on its connection (the device
 * model's): at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a sign-in that is rolled back.
 *
 * The context carries the guard, the client, the identity, the method, and the
 * device the client proved it holds, if any; its principal and tenant are
 * `null`, since none is chosen yet. Never carries the choice token or the list
 * of principals.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalChoiceRequired extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        // Who is signing in, how, and from which client.
        EventContext $context,

        /** When the choice stops being usable. */
        public CarbonImmutable $expiresAt,
    ) {
        parent::__construct($context);
    }
}
