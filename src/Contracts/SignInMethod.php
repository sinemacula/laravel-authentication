<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Proves who is signing in from the input a client sent, answering with the
 * first factor it verified or why it did not.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SignInMethod
{
    /**
     * The type of identifier the method signs in to the guard with, such as
     * `email`, or `null` when it uses none.
     *
     * @param  string  $guard
     * @return ?string
     */
    public function identifierType(string $guard): ?string;

    /**
     * The identifier the input names for the guard, as given, or `null` when it
     * names none.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string;

    /**
     * The id of the challenge the input answers when it is in the form the
     * method issues, or `null`.
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
