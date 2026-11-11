<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched once a sign-in that leaves its session pending is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionPending implements AuthenticationEvent
{
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
