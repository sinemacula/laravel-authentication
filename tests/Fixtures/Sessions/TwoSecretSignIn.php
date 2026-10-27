<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Sign-in method double that checks two secrets against the account its email
 * address finds, a password and a PIN, and counts each check against the
 * account before making it, as a method that checks more than one secret must.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TwoSecretSignIn implements SignInMethod
{
    /** @var string The PIN every account accepts. */
    public const string PIN = '2468';

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
     * Check the password and then the PIN, each counted against the account.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
     */
    #[\Override]
    public function authenticate(SignInRequest $request): Identity|SignInFailureReason
    {
        $email    = $this->identifier($request->guard, $request->input);
        $identity = $email === null ? null : $request->provider->retrieveByCredentials(['email' => $email]);

        if (!$identity instanceof Identity) {
            return SignInFailureReason::INVALID_CREDENTIALS;
        }

        $password = $request->reserveAccountAttempt($identity)
            && $request->provider->validateCredentials($identity, ['password' => $request->input['password'] ?? null]);

        return $password && $request->reserveAccountAttempt($identity) && ($request->input['pin'] ?? null) === self::PIN
            ? $identity
            : SignInFailureReason::INVALID_CREDENTIALS;
    }
}
