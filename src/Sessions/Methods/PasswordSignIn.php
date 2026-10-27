<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The password sign-in method: an identifier and a password, checked against
 * the identity's stored hash through the guard's identity provider.
 *
 * The identifier key comes from `authentication.sign_in.password_identifier`
 * (default `email`). `authenticate()` passes the provider only that key and
 * `password`, so no other input key reaches a query. `verifyCredentials()` is
 * the credential path `attempt()` and `validate()` use: it takes the caller's
 * credentials as the provider understands them, closures included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordSignIn implements SignInMethod
{
    /** @var string Name of the method, under which it is registered and recorded. */
    public const string NAME = 'password';

    /** @var string Configuration key naming the identifier column. */
    private const string IDENTIFIER_KEY = 'authentication.sign_in.password_identifier';

    /** @var string Identifier column used when the configuration has no key for it. */
    private const string DEFAULT_IDENTIFIER = 'email';

    /** @var string Input key holding the password. */
    private const string PASSWORD_KEY = 'password';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the identifier key is read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The configured identifier key, which is also the identifier's type:
     * `email` when the configuration has no key for it.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function identifierType(): string
    {
        $key = $this->config->get(self::IDENTIFIER_KEY, self::DEFAULT_IDENTIFIER);

        if (!is_string($key) || preg_match('/^[a-z][a-z0-9_]*$/D', $key) !== 1 || str_contains($key, self::PASSWORD_KEY)) {

            $message = sprintf(
                '%s must name the identifier column in lower case (a letter, then letters, digits or underscores) and must not contain `password`.',
                self::IDENTIFIER_KEY,
            );

            throw new \InvalidArgumentException($message);
        }

        return $key;
    }

    /**
     * The identifier the input names under the configured key, when it is a
     * string.
     *
     * @param  array<array-key, mixed>  $input
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function identifier(#[\SensitiveParameter] array $input): ?string
    {
        $identifier = $input[$this->identifierType()] ?? null;

        return is_string($identifier) ? $identifier : null;
    }

    /**
     * Verify the identifier and password the input carries. Anything else in
     * the input is ignored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): Identity|SignInFailureReason
    {
        $key      = $this->identifierType();
        $password = $request->input[self::PASSWORD_KEY] ?? null;

        $credentials = [
            $key               => $this->identifier($request->input),
            self::PASSWORD_KEY => is_string($password) ? $password : null,
        ];

        return $this->verifyCredentials($request->provider, $credentials) ?? SignInFailureReason::INVALID_CREDENTIALS;
    }

    /**
     * Return the identity the credentials find whose stored hash matches their
     * password, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  array<array-key, mixed>  $credentials
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function verifyCredentials(IdentityProvider $provider, #[\SensitiveParameter] array $credentials): ?Identity
    {
        $user = $this->retrieve($provider, $credentials);

        return $user instanceof Identity && $this->accepts($provider, $user, $credentials) ? $user : null;
    }

    /**
     * Look up the account the credentials name, from the write connection, as
     * the provider reads it, whether or not their password matches.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    public function retrieve(IdentityProvider $provider, #[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        return $provider->retrieveByCredentials($credentials);
    }

    /**
     * Whether the credentials' password matches the account's stored hash. No
     * account is never accepted, and no hash is computed for it: the caller's
     * timebox evens out the time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    public function accepts(IdentityProvider $provider, ?Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        return $user !== null && $provider->validateCredentials($user, $credentials);
    }
}
