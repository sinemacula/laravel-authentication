<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Sign-in method double that stands for any method that has already proven its
 * input (an accepted one-time code, an SSO assertion, a passkey): it returns
 * the identity the input's email address finds, checking nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvenIdentitySignIn implements SignInMethod
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
     * The email address the input names.
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
     * Return the identity the email address finds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|Identity
    {
        $email    = $this->identifier($request->guard, $request->input);
        $identity = $email === null ? null : $request->provider->retrieveByCredentials(['email' => $email]);

        return $identity instanceof Identity ? $identity : FailureReason::INVALID_CREDENTIALS;
    }
}
