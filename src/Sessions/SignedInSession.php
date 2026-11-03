<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;

/**
 * A session the session service started, refreshed or switched: who signed in,
 * as which principal, its record, how, and its token pair. The client keeps the
 * refresh token (a cookie application's browser keeps it in the pair's cookie)
 * to refresh the session, or to have a later sign-in replace it.
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
     * @internal `$heldSlots` is the session service's; an application reads the
     *     session, its tokens and how it was started
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @param  string  $method
     * @param  list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation>  $heldSlots
     */
    public function __construct(

        /** Identity that signed in. */
        public Identity $identity,

        /** Principal the session acts as. */
        public Principal $principal,

        /** The session record: refresh state, deadlines and revocation. */
        public EloquentSession&Model $record,

        /** The first access and refresh tokens of the session. */
        public TokenPair $tokens,

        /** Name of the sign-in method that started the session. */
        public string $method,

        /** The slots its pending sign-in held, which the session service gives back once it binds it. */
        public array $heldSlots = [],
    ) {}
}
