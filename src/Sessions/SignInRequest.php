<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * What a sign-in method is asked to verify: the input a client sent to a guard,
 * with the guard's identity provider to look the identity up through and the
 * client the input came from.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInRequest
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     */
    public function __construct(

        /** Guard the sign-in is for. */
        public string $guard,

        /** The guard's identity provider, which looks identities up. */
        public IdentityProvider $provider,

        /** Input the client sent, secrets included. */
        #[\SensitiveParameter] public array $input,

        /** Client the input came from. */
        public ClientContext $client,
    ) {}
}
