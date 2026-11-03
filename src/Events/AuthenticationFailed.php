<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Dispatched once for every failed sign-in, refresh, switch and request access
 * token, with the flow and a machine-readable reason. Where Laravel's `Failed`
 * fires as well, this one follows it.
 *
 * Carries as much context as the flow established before it failed: the
 * identity only once a sign-in method verified it or a token's subject loaded
 * (a wrong password or an unknown identifier carries none), the principal and
 * tenant only once resolved, and the session, or the id a token named when no
 * session row was found. The identifier is the one a sign-in's input named, as
 * given. Never a password, a code, a token or any other secret.
 *
 * It says why a sign-in failed even where the client is not told: a refusal by
 * the account's own limit is `account_rate_limited` here, with the wait, while
 * the sign-in's result says `invalid_credentials`, so listeners (lockout
 * notices, a SIEM) can tell a locked account from a wrong password.
 *
 * A failed check of a challenge the package issued (a one-time code checked as
 * a sign-in, a factor, an identifier's verification or change, a password
 * reset, or a passkey ceremony signed in or reauthenticated with) carries the
 * challenge's id, which the further-factor package's own per-attempt events
 * share, so a listener can follow every attempt at one challenge. An id that is
 * not in the form the package issues is never carried.
 *
 * Reported once for each refusal: a guard settles and reports its request's
 * credential at most once, each service call reports its own refusal once, and
 * reading the caller reports a refused refresh or pending credential once per
 * guard and credential. Building the authentication context reports nothing.
 * Guards of one kind listed on one route each report their own refusal of the
 * credential, naming their guard: they are different applications' refusals.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationFailed implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
     * @param  ?string  $challengeId
     */
    public function __construct(

        /** Who and what the failure concerned, as far as the flow got. */
        public EventContext $context,

        /** The flow that failed. */
        public AuthenticationFlow $flow,

        /** Machine-readable failure reason. */
        public FailureReason $reason,

        /** Identifier a sign-in's input named, as given, if any. */
        public ?string $identifier = null,

        /** Seconds until another attempt may be made, for `rate_limited` and `account_rate_limited` only. */
        public ?int $retryAfter = null,

        /** The id of the challenge (a one-time code's or a passkey ceremony's) the failed check answered, when it is in the form the package issues; `null` otherwise. */
        public ?string $challengeId = null,
    ) {}

    /**
     * Return who and what the failure concerned.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
