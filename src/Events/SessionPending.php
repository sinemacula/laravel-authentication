<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when a sign-in leaves its session pending instead of activating
 * it: the credential (or, through `start()` or `signInExternally()`, something
 * outside the guard) proved the identity, and a further factor is required, a
 * principal is to be chosen, or both. From `signIn()` it is the outcome of that
 * sign-in's `Attempting`; from `start()` and `signInExternally()`, which
 * dispatch no `Attempting`, it is the only event. The session's activation
 * dispatches `SessionCreated` and `SignedIn`.
 *
 * Dispatched once the pending session is committed on the session's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a sign-in that is rolled back.
 *
 * The context carries the guard, the client, the identity, the principal and
 * active tenant when one is selected (`null` while the choice is outstanding),
 * the pending session and the method. `requires` lists what the session waits
 * on, in order (`mfa`, `principal`). Never carries the pending credential or
 * any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionPending implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  list<string>  $requires
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Who is signing in, on which pending session, how, and from which client. */
        public EventContext $context,

        /** What the session waits on, in order. */
        public array $requires,

        /** When the pending credential, and the session with it, ends unless it activates. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * Return who is signing in, on which pending session, and how.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
