<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Dispatched once for every failed sign-in, refresh, principal switch and
 * request access token, with the flow and a machine-readable reason. Where
 * Laravel's `Failed` fires as well, this one follows it.
 *
 * Carries as much context as the flow established before it failed: the
 * identity only once a sign-in method verified it or a token's subject loaded
 * (a wrong password or an unknown identifier carries none), the principal and
 * tenant only once resolved, and the device, or the id a token named when no
 * device row was found. The identifier is the one a sign-in's input named, as
 * given. Never a password, a code, a token or any other secret.
 *
 * It says why a sign-in failed even where the client is not told: a refusal by
 * the account's own limit is `account_rate_limited` here, with the wait, while
 * the sign-in's result says `invalid_credentials`, so listeners (lockout
 * notices, a SIEM) can tell a locked account from a wrong password.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationFailed implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
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
