<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Sign-in method contract.
 *
 * A sign-in method proves who is signing in from the input a client sent: a
 * password, a one-time code, an external provider's assertion. It answers with
 * what it verified (a `FirstFactor`: the identity, the channel it proved itself
 * over, what was observed about the authenticator, and the `amr` values the
 * proof stands for), or why it did not; everything after that (activity, the
 * principal, the application policy, a further factor, the session, its proofs
 * and the tokens) belongs to the session service, so every method ends in the
 * same place. The session records the first factor as its first proof and
 * derives the access token's `amr` from its values; `mfa` is reserved and a
 * `FirstFactor` refuses it.
 *
 * Methods are registered on the `SignInMethodManager` under the name the
 * session service records on the session and the application policy allows per
 * guard. The manager keeps one instance per name for the life of the process,
 * so a method must hold no state between calls (Octane, queue workers), and it
 * must never bind a guard, issue tokens or write session state itself. Its
 * timing must not reveal more than the session service's timebox hides: do the
 * same work whether or not the identifier exists. A method that looks an
 * identity up and then checks a secret counts the check against the account
 * with `SignInRequest::reserveAccountAttempt()` before making it, so the
 * account's own limit bounds the guesses at its secret however the identity was
 * found.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SignInMethod
{
    /**
     * The type of identifier the method signs in to the guard with (for example
     * `email`), or `null` when it uses none. It names the identifier's
     * normaliser, the form the attempt limits count it in, and the identifier a
     * guard that requires verified identifiers checks.
     *
     * @param  string  $guard
     * @return ?string
     */
    public function identifierType(string $guard): ?string;

    /**
     * The identifier the input names for the guard, as given, or `null` when it
     * names none. Used for the attempt limits and the failure event, never to
     * look the identity up.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string;

    /**
     * The id of the challenge the input answers (a one-time code's, a passkey
     * ceremony's) when it is in the form the method issues, or `null` for a
     * method that answers none and for an id in any other form. The session
     * service reports it with every failure of the method's sign-in or
     * reauthentication, so a listener can follow every attempt at one
     * challenge; it never looks anything up with it.
     *
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    public function challenge(#[\SensitiveParameter] array $input): ?string;

    /**
     * Verify the input and return the first factor it proves, or why it does
     * not.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     */
    public function authenticate(SignInRequest $request): FailureReason|FirstFactor;
}
