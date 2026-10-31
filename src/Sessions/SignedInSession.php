<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;

/**
 * A session the session service started: who signed in, as which principal, on
 * which device, how, and the first token pair, whose refresh token the client
 * must keep to refresh the session or sign in again on the same device.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedInSession
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @param  string  $method
     * @param  bool  $deviceCreated
     */
    public function __construct(

        /** Identity that signed in. */
        public Identity $identity,

        /** Principal the session acts as. */
        public Principal $principal,

        /** Device holding the session. */
        public EloquentDevice&Model $device,

        /** The first access and refresh tokens of the session. */
        public TokenPair $tokens,

        /** Name of the sign-in method that started the session. */
        public string $method,

        /** Whether the device was created, rather than an existing one of the client continued. */
        public bool $deviceCreated,
    ) {}
}
