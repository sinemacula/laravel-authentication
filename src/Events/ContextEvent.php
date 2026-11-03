<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Base of the package events that carry nothing but their context: the event's
 * class says what happened, and the context who and what it happened to. Like
 * every package event it holds plain values only, so it crosses a queue as it
 * is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ContextEvent implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the event is about. */
        public EventContext $context,
    ) {}

    /**
     * Return who and what the event is about.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
