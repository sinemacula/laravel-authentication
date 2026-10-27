<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * What a sign-in method is asked to verify: the input a client sent to a guard,
 * with the guard's identity provider to look the identity up through and the
 * client the input came from, and the account limits to count each secret it
 * checks against.
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
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\AccountAttempts  $accountAttempts
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

        /** The sign-in's slots on the limits of the accounts it checks, or `null` for a request built outside a sign-in, which counts nothing. */
        private ?AccountAttempts $accountAttempts = null,
    ) {}

    /**
     * Count a check of a secret against the account it is for, before the check
     * is made. Returns `false` when the account has no attempts left: then do
     * not check the secret, and answer `invalid_credentials`, as for a wrong
     * one, so the refusal does not reveal that the account exists.
     *
     * A method that looks an identity up and then checks a secret it was given
     * calls this once it has the identity: a lookup can find one account by
     * many spellings of an identifier, and through every guard whose provider
     * returns it, so only the account's own count bounds the guesses at its
     * secret. Call it before each secret checked: a method that checks two
     * takes two slots. Every slot is the sign-in's: given back when it starts a
     * session, kept by a pending sign-in until that completes, and left counted
     * when it fails.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    public function reserveAccountAttempt(Identity $identity): bool
    {
        return $this->accountAttempts?->reserve($identity) ?? true;
    }
}
