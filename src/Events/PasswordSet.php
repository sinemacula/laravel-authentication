<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;

/**
 * Dispatched when `Auth::passwords()->set()`, or a password reset, sets an
 * identity's password: at a registration, a change or a reset, as the flow
 * says.
 *
 * Fired only once the new hash is committed on the identity's own connection:
 * at once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for one that is rolled back. The sessions the
 * flow ends are reported by their own `DeviceRevoked` and `SignedOutEverywhere`
 * events. Never fired by the automatic rehash of a password on sign-in.
 *
 * The context carries the guard, the client the request came from and the
 * identity, and, for a change that kept the device it was made from signed in,
 * that device. It carries no password or hash.
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
