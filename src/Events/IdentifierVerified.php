<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched once the verification of an identity's identifier is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierVerified implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $type
     */
    public function __construct(

        /** The identity whose identifier was verified, and the client that proved it. */
        public EventContext $context,

        /** Type of the identifier verified, for example `email`. */
        public string $type,
    ) {}

    /**
     * Return the identity whose identifier was verified.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
