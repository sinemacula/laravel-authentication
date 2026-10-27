<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The password sign-in method: an identifier and a password, checked against
 * the identity's stored hash through the guard's identity provider.
 *
 * The identifier key comes from the guard's own
 * `auth.guards.<name>.sign_in.password_identifier` when it sets one, otherwise
 * from `authentication.sign_in.password_identifier` (default `email`), so each
 * guard can sign in by the column its identities are found by. `authenticate()`
 * passes the provider only that key and `password`, so no other input key
 * reaches a query. `verifyCredentials()` is the credential path `attempt()` and
 * `validate()` use: it takes the caller's credentials as the provider
 * understands them, closures included. Neither rehashes: a sign-in that is
 * admitted calls `rehash()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordSignIn implements SignInMethod
{
    /** @var string Name of the method, under which it is registered and recorded. */
    public const string NAME = 'password';

    /** @var string Configuration key naming the identifier column for every guard that does not name its own. */
    private const string IDENTIFIER_KEY = 'authentication.sign_in.password_identifier';

    /** @var string Key of a guard's own sign-in block. */
    private const string GUARD_BLOCK = 'sign_in';

    /** @var string Key naming the identifier column in a guard's sign-in block. */
    private const string GUARD_IDENTIFIER_KEY = 'password_identifier';

    /** @var string Identifier column used when the configuration has no key for it. */
    private const string DEFAULT_IDENTIFIER = 'email';

    /** @var string Input key holding the password. */
    private const string PASSWORD_KEY = 'password';

    /** @var string Laravel's setting for rehashing a password on sign-in. */
    private const string REHASH_KEY = 'hashing.rehash_on_login';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the identifier keys are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The identifier key the guard is configured with, which is also the
     * identifier's type: the guard's own `sign_in.password_identifier` when it
     * sets one, otherwise the package's, and `email` when neither does.
     *
     * @param  string  $guard
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function identifierType(string $guard): string
    {
        [$key, $setting] = $this->configuredIdentifier($guard);

        if (!is_string($key) || !IdentifierType::isValid($key) || str_contains($key, self::PASSWORD_KEY)) {

            $message = sprintf(
                '%s must name the identifier column in lower case (a letter, then letters, digits or underscores) and must not contain `password`.',
                $setting,
            );

            throw new \InvalidArgumentException($message);
        }

        return $key;
    }

    /**
     * The identifier the input names under the guard's identifier key, when it
     * is a string.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string
    {
        $identifier = $input[$this->identifierType($guard)] ?? null;

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
        $key      = $this->identifierType($request->guard);
        $password = $request->input[self::PASSWORD_KEY] ?? null;

        $credentials = [
            $key               => $this->identifier($request->guard, $request->input),
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
     * Rehash the identity's password through the provider when its stored hash
     * no longer matches the hasher's current algorithm or cost, unless
     * Laravel's `hashing.rehash_on_login` setting turns that off. Called only
     * after a password sign-in is admitted, so a request authenticated by a
     * bearer token or a refresh never writes a password.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<array-key, mixed>  $credentials
     * @return void
     */
    public function rehash(IdentityProvider $provider, Identity $identity, #[\SensitiveParameter] array $credentials): void
    {
        if (!(bool) $this->config->get(self::REHASH_KEY, true)) {
            return;
        }

        $provider->rehashPasswordIfRequired($identity, $credentials);
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

    /**
     * The identifier key the guard's configuration gives, and the setting it
     * comes from: the guard's `sign_in.password_identifier` when its `sign_in`
     * block sets one, otherwise the package's. A guard `sign_in` block that is
     * not an array, or sets anything else, fails closed.
     *
     * @param  string  $guard
     * @return array{0: mixed, 1: string}
     *
     * @throws \InvalidArgumentException
     */
    private function configuredIdentifier(string $guard): array
    {
        $config = $this->config->get("auth.guards.{$guard}");
        $block  = is_array($config) ? $config[self::GUARD_BLOCK] ?? null : null;

        if ($block === null) {
            return [$this->config->get(self::IDENTIFIER_KEY, self::DEFAULT_IDENTIFIER), self::IDENTIFIER_KEY];
        }

        if (!is_array($block) || array_diff(array_keys($block), [self::GUARD_IDENTIFIER_KEY]) !== []) {
            throw new \InvalidArgumentException(sprintf('auth.guards.%s.%s must be an array that sets only `%s`.', $guard, self::GUARD_BLOCK, self::GUARD_IDENTIFIER_KEY));
        }

        return array_key_exists(self::GUARD_IDENTIFIER_KEY, $block)
            ? [$block[self::GUARD_IDENTIFIER_KEY], sprintf('auth.guards.%s.%s.%s', $guard, self::GUARD_BLOCK, self::GUARD_IDENTIFIER_KEY)]
            : [$this->config->get(self::IDENTIFIER_KEY, self::DEFAULT_IDENTIFIER), self::IDENTIFIER_KEY];
    }
}
