<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;

/**
 * Dispatched once an identity's new password hash is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordSet extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     */
    public function __construct(

        // The identity whose password was set, and the client that set it.
        EventContext $context,

        /** Why the password was set: a registration, a change or a reset. */
        public PasswordFlow $flow,
    ) {
        parent::__construct($context);
    }
}
