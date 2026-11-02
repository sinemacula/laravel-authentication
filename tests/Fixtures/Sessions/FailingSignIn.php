<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Sign-in method double with a bug: it throws while verifying the input it was
 * given, as a method whose client library failed would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailingSignIn implements SignInMethod
{
    /**
     * The method signs in by email address.
     *
     * @param  string  $guard
     * @return string
     */
    #[\Override]
    public function identifierType(string $guard): string
    {
        return 'email';
    }

    /**
     * The email address the input names, when it is a string.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    #[\Override]
    public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string
    {
        return is_string($input['email'] ?? null) ? $input['email'] : null;
    }

    /**
     * Fail while verifying.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|FirstFactor
    {
        throw new \RuntimeException('a bug in the sign-in method for ' . $request->guard);
    }
}
