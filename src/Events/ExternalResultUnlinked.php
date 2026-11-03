<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when an adapter signs in or reauthenticates with a result an
 * external identity provider verified, and the link contract links the
 * connection, issuer and subject to no identity. The sign-in or
 * reauthentication then fails as `external_result_unlinked`, and
 * `AuthenticationFailed` follows this.
 *
 * Informational only: nothing is created from it. The package that verified the
 * result, and links its results to identities, provisions (or refuses) on its
 * own event, before it hands the result over; provisioning on this one as well
 * would provision twice.
 *
 * The context carries the guard and the client, no identity, and the connection
 * and the authorisation request's public reference, when the result had one, as
 * every event of a redemption does. The connection and the issuer say where the
 * result came from; the subject, and everything else the provider asserted, is
 * never carried.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResultUnlinked implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $connectionId
     * @param  string  $issuer
     */
    public function __construct(

        /** The application the result was handed to, and the client. */
        public EventContext $context,

        /** The connection the result came through. */
        public string $connectionId,

        /** The issuer the provider asserted. */
        public string $issuer,
    ) {}

    /**
     * Return the application the result was handed to, and the client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
