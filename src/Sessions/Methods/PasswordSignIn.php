<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The password sign-in method: an identifier and a password, checked against
 * the identity's stored hash through the guard's identity provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordSignIn implements SignInMethod
{
    /** @var string Name of the method, under which it is registered and recorded. */
    public const string NAME = 'password';

    /** @var string The `amr` value of a password (RFC 8176). */
    public const string AMR = 'pwd';

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
     * identifier's type.
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
     * The identifier the input names under the guard's identifier key, as a
     * string, when it is a string, a `Stringable` or an integer.
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
     * A password answers no challenge.
     *
     * @param  array<array-key, mixed>  $input
     * @return null
     */
    #[\Override]
    public function challenge(#[\SensitiveParameter] array $input): null
    {
        return null;
    }

    /**
     * The credentials `attempt()` looks the account up by, or `null` when the
     * identifier is of a type the identifier's limit cannot count.
     *
     * An integer is looked up as a string so MySQL never compares it loosely.
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
     * password check against the account the identifier finds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|FirstFactor
    {
        $identifier = $this->identifier($request->guard, $request->input());
        $password   = $request->input()[self::PASSWORD_KEY] ?? null;

        if ($identifier === null) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        $credentials = [
            $this->identifierType($request->guard) => $identifier,
            self::PASSWORD_KEY                     => is_string($password) ? $password : null,
        ];

        $user = $this->retrieve($request->provider, $credentials);

        return $user instanceof Identity && self::hasPassword($user) && $request->reserveAccountAttempt($user) && $request->provider->validateCredentials($user, $credentials)
            ? new FirstFactor($user, new Channel(ChannelKind::PASSWORD), methods: [self::AMR])
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
     * Rehash the identity's password when its stored hash is outdated, unless
     * `hashing.rehash_on_login` turns that off.
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

        // `#[\SensitiveParameter]` does not cover what a closure captures.
        $held = new \SensitiveParameterValue($credentials);

        Container::getInstance()->make(Rehashing::class)->during($identity, $credentials['password'] ?? null, static function () use ($provider, $identity, $held): void {
            $provider->rehashPasswordIfRequired($identity, $held->getValue());
        });
    }

    /**
     * Look up the account the credentials name, whether or not their password
     * matches.
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
     * account; `false` when the account has no attempts left.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts  $attempts
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
        return self::hasPassword($identity) && $attempts->reserve($identity) && $provider->validateCredentials($identity, $credentials);
    }

    /**
     * Whether the credentials' password matches the account's stored hash.
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
        return $user !== null && self::hasPassword($user) && $provider->validateCredentials($user, $credentials);
    }

    /**
     * Whether the account can hold a password credential.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     */
    private static function hasPassword(Authenticatable $user): bool
    {
        return !$user instanceof MachineIdentity;
    }

    /**
     * The identifier key the guard's configuration gives, and the setting it
     * comes from.
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
