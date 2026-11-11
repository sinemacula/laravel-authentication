<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched once a requested change of an identity's identifier, waiting for
 * its proof, is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeRequested implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $type
     * @param  string  $identifier
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The identity whose identifier would change, and the client that asked. */
        public EventContext $context,

        /** Type of the identifier, for example `email`. */
        public string $type,

        /** The identifier the change would set, in its normal form. */
        public string $identifier,

        /** When the change stops waiting for its proof. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * Return the identity whose identifier would change.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
