<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when an identity's identifier of a type (its email address, its
 * phone number) is verified.
 *
 * Fired only by the call that recorded the verification, not for one already
 * verified, and only once the record is committed on the identity's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a record that is rolled back.
 *
 * The context carries the guard the verification was made for, the identity,
 * and the client that proved the identifier (the request being served when the
 * caller named none). It carries no identifier, code, link or token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierVerified implements AuthenticationEvent
{
    use SerializesModels;

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
