<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Base of the package events that carry nothing but their context: the event's
 * class says what happened, and the context who and what it happened to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ContextEvent implements AuthenticationEvent
{
    use SerializesModels {
        __unserialize as private restoreSerializedProperties;
    }

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
     * Restore the event after serialization.
     *
     * The context is restored here because PHP 8.3 lets only the declaring
     * class initialise a readonly property, and the trait's restore writes from
     * the subclass's scope.
     *
     * @param  array<string, mixed>  $values
     * @return void
     *
     * @SuppressWarnings("php:S100")
     */
    public function __unserialize(array $values): void
    {
        /** @var \SineMacula\Laravel\Authentication\Events\EventContext $context */
        $context = $this->getRestoredPropertyValue($values['context']);

        $this->context = $context;

        unset($values['context']);

        $this->restoreSerializedProperties($values);
    }

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
