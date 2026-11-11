<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched once an identity's identifier is replaced by one it proved.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChanged implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $type
     * @param  ?string  $previous
     * @param  string  $identifier
     * @param  \Carbon\CarbonImmutable  $changedAt
     */
    public function __construct(

        /** The identity whose identifier changed, and the client that confirmed it. */
        public EventContext $context,

        /** Type of the identifier, for example `email`. */
        public string $type,

        /** The identifier replaced, as it was stored, or `null` when there was none. */
        public ?string $previous,

        /** The identifier that replaced it, in its normal form. */
        public string $identifier,

        /** When the change was made. */
        public CarbonImmutable $changedAt,
    ) {}

    /**
     * Return the identity whose identifier changed.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
