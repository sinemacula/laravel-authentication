<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when a change of an identity's identifier of a type (its email
 * address, its phone number) is requested and waits for its proof, once the
 * request is committed on the identity's connection: at once when that
 * connection has no open transaction, after its transaction commits otherwise,
 * and never for a request that is rolled back.
 *
 * The context carries the guard the change was requested through, the identity
 * and the client that asked. The new identifier is a snapshot in its normal
 * form, so a queued audit listener needs no query back; it is not a secret. It
 * carries no code, link or token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeRequested implements AuthenticationEvent
{
    use SerializesModels;

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
