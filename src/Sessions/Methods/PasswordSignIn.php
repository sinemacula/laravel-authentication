<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The password sign-in method: an identifier and a password, checked against
 * the identity's stored hash through the guard's identity provider.
 *
 * The identifier key comes from the guard's own
 * `auth.guards.<name>.sign_in.password_identifier` when it sets one, otherwise
 * from `authentication.sign_in.password_identifier` (default `email`), so each
 * guard can sign in by the column its identities are found by. `authenticate()`
 * passes the provider only that key, with a string value, and `password`, so no
 * other input key reaches a query.
 *
 * Every password checked for a sign-in is counted against the account it is
 * checked for, on top of the identifier's and the IP address's limits the
 * caller takes, and the slot is the sign-in's to give back: a lookup can find
 * one account by many spellings of its identifier, and through every guard
 * whose provider returns it, so the account's own count, held to the most
 * permissive limit among those guards, is what bounds the guesses made at its
 * password, and at a further factor its sign-in waits for.
 *
 * `verifyCredentials()` is the credential path `validate()` uses: it takes the
 * caller's credentials as the provider understands them, closures included, and
 * counts nothing. None of them rehashes: a sign-in that is admitted calls
 * `rehash()`. `lookupCredentials()`, `retrieve()`, `verifyPassword()` and
 * `accepts()` exist for the guard's `attempt()` and are internal: they are not
 * part of the method's API and may change without notice.
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
     * is a string, a `Stringable` or an integer (a numeric column's value sent
     * as a JSON number), as a string.
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

        return is_string($identifier) || is_int($identifier) || $identifier instanceof \Stringable ? (string) $identifier : null;
    }

    /**
     * The credentials `attempt()` looks the account up by, or `null` when they
     * must not be looked up. They are looked up when they leave the guard's
     * identifier key out (and find the account by other keys) or give it a
     * string, a `Stringable`, an integer or a query closure; an integer is
     * looked up as its string form, the form it is counted in and `signIn()`
     * looks it up by, so a database that compares a string column with a number
     * loosely (as MySQL does) never matches an account by it. Anything else
     * under the key (a list of values, a float, a boolean, `null`) would let
     * one attempt reach accounts the identifier's limit never counts, so it is
     * refused before any lookup.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $credentials
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function lookupCredentials(string $guard, #[\SensitiveParameter] array $credentials): ?array
    {
        $key = $this->identifierType($guard);

        if (!array_key_exists($key, $credentials) || $credentials[$key] instanceof \Closure) {
            return $credentials;
        }

        $identifier = $this->identifier($guard, $credentials);

        if ($identifier === null) {
            return null;
        }

        return is_int($credentials[$key]) ? [...$credentials, $key => $identifier] : $credentials;
    }

    /**
     * Verify the identifier and password the input carries, counting the
     * password check against the account the identifier finds. Anything else in
     * the input is ignored, and an identifier that is neither a string, a
     * `Stringable` nor an integer is refused without a lookup.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|Identity
    {
        $identifier = $this->identifier($request->guard, $request->input);
        $password   = $request->input[self::PASSWORD_KEY] ?? null;

        if ($identifier === null) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        $credentials = [
            $this->identifierType($request->guard) => $identifier,
            self::PASSWORD_KEY                     => is_string($password) ? $password : null,
        ];

        $user = $this->retrieve($request->provider, $credentials);

        return $user instanceof Identity && $request->reserveAccountAttempt($user) && $request->provider->validateCredentials($user, $credentials)
            ? $user
            : FailureReason::INVALID_CREDENTIALS;
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
     * bearer token or a refresh never writes a password. The rehash runs marked
     * by `Rehashing`, so a listener that ends sessions on a change of password
     * does not take it for one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<array-key, mixed>  $credentials
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function rehash(IdentityProvider $provider, Identity $identity, #[\SensitiveParameter] array $credentials): void
    {
        if (!(bool) $this->config->get(self::REHASH_KEY, true)) {
            return;
        }

        Container::getInstance()->make(Rehashing::class)->during(static function () use ($provider, $identity, $credentials): void {
            $provider->rehashPasswordIfRequired($identity, $credentials);
        });
    }

    /**
     * Look up the account the credentials name, from the write connection, as
     * the provider reads it, whether or not their password matches.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     *
     * @internal
     */
    public function retrieve(IdentityProvider $provider, #[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        return $provider->retrieveByCredentials($credentials);
    }

    /**
     * Check the credentials' password for a sign-in, counted against the
     * account: a slot of the account's limit is taken first and held by the
     * sign-in's account attempts, which give it back only if the sign-in
     * succeeds. When the account has no attempts left, its password is not
     * checked and the answer is `false`, as for a wrong password, so the
     * refusal does not reveal that the account exists.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccountAttempts  $attempts
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     *
     * @imperative
     */
    public function verifyPassword(AccountAttempts $attempts, IdentityProvider $provider, Identity $identity, #[\SensitiveParameter] array $credentials): bool
    {
        return $attempts->reserve($identity) && $provider->validateCredentials($identity, $credentials);
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
     *
     * @internal
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
