<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Dispatched when an identity's identifier of a type (its email address, its
 * phone number) is verified.
 *
 * Fired only by the call that recorded the verification, not for one already
 * verified, and only once the record is committed on the identity's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a record that is rolled back. It
 * carries no identifier, code, link or token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierVerified
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     */
    public function __construct(

        /** Name of the guard the verification was made for. */
        public string $guard,

        /** The identity whose identifier was verified. */
        public Identity $identity,

        /** Type of the identifier verified, for example `email`. */
        public string $type,

        /** The client that proved the identifier, when there was one. */
        public ?ClientContext $client = null,
    ) {}
}
