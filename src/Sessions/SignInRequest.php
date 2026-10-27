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
 * The session service builds the request for each sign-in. To unit-test a
 * method, build one yourself: with no reservation callback every account check
 * is allowed, and with one such as `fn (Identity $identity): bool => false`
 * every account has used up its attempts.
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
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): bool)|null  $reserveAccountAttempt
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

        /** Takes a slot on an account's limit for the sign-in and says whether it had one, or `null` for a request built outside a sign-in, which counts nothing. */
        private ?\Closure $reserveAccountAttempt = null,
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
     * when it fails. A limit configured wrongly throws its
     * `InvalidArgumentException` from here.
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
