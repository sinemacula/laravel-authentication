<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;

/**
 * Dispatched once the redemption of a result an external identity provider
 * verified is committed.
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
