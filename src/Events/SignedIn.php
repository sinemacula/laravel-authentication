<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched once a sign-in, or a refresh that renews a session, is committed.
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
