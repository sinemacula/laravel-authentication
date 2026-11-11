<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * What a sign-in method is asked to verify: the client's input, the guard's
 * identity provider and the client.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInRequest
{
    /** @var \SensitiveParameterValue The input the client sent, secrets included. */
    private \SensitiveParameterValue $input;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): bool)|null  $reserveAccountAttempt
     */
    public function __construct(

        /** Guard the sign-in is for. */
        public string $guard,

        /** The guard's identity provider, which looks identities up. */
        public IdentityProvider $provider,

        // Input the client sent, secrets included.
        #[\SensitiveParameter]
        array $input,

        /** Client the input came from. */
        public ClientContext $client,

        /** Takes a slot on an account's limit for the sign-in and says whether it had one, or `null` for a request built outside a sign-in, which counts nothing. */
        private ?\Closure $reserveAccountAttempt = null,
    ) {
        $this->input = new \SensitiveParameterValue($input);
    }

    /**
     * The input the client sent, secrets included: read what the method needs
     * from it, and never log it.
     *
     * @return array<array-key, mixed>
     */
    public function input(): array
    {
        return $this->input->getValue();
    }

    /**
     * Count a check of a secret against the account it is for; `false` when the
     * account has no attempts left.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     *
     * @phpstan-impure
     *
     * @imperative
     */
    public function reserveAccountAttempt(Identity $identity): bool
    {
        return $this->reserveAccountAttempt === null || ($this->reserveAccountAttempt)($identity);
    }
}
