<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when the session service holds a sign-in for a further factor
 * instead of starting its session: the sign-in method proved the identity (or,
 * through `start()`, something outside the guard did), the identity, principal
 * and tenant were admitted, and the additional-factor policy asked for more.
 * From `signIn()` it is the outcome of that sign-in's `Attempting`; from
 * `start()`, which dispatches no `Attempting`, it is the only event. Completing
 * the pending sign-in dispatches `SignedIn`, and discarding it
 * `AuthenticationFailed` with `additional_factor_failed`.
 *
 * Dispatched once the pending sign-in is committed on its connection (the
 * device model's): at once when that connection has no open transaction, after
 * its transaction commits otherwise, and never for a sign-in that is rolled
 * back.
 *
 * The context carries the guard, the client, the identity, principal and
 * tenant, the method, and the device the client proved it holds, which the
 * session would continue on, if any. Never carries the pending token, a
 * credential or any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdditionalFactorRequired implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Who is signing in, as which principal, how, and from which client. */
        public EventContext $context,

        /** When the pending sign-in stops being completable. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * Return who is signing in, as which principal, and how.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
