<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Dispatched once for every failed sign-in, refresh, switch and request access
 * token, with the flow and a machine-readable reason.
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

        /** Id of the challenge the failed check answered, when it is in the form the package issues. */
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
