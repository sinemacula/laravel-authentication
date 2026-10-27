<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Support\Manager;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The registry of sign-in methods, keyed by the name each is recorded under on
 * the devices it signs in and allowed under in a guard's audience policy.
 *
 * The package registers `password`, which `attempt()` and `validate()` also use
 * directly, so the name is reserved: `extend('password', ...)` throws. Other
 * methods register themselves with `extend()` under a lower-case name (a
 * letter, then letters, digits or underscores), for example from a service
 * provider:
 *
 * `$app->make(SignInMethodManager::class)->extend('sso', fn ($app) => $app->make(SsoSignIn::class));`
 *
 * A singleton that keeps each method it builds for the life of the process,
 * which is why methods must be stateless. There is no default method: every
 * sign-in names the method it uses, exactly as it was registered, since the
 * name is what the device records and the audience policy allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SignInMethodManager extends Manager
{
    /** @var string Pattern a registered method's name must match. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]*$/D';

    /**
     * Return the sign-in method registered under the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Contracts\SignInMethod
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function method(string $name): SignInMethod
    {
        return self::assertSignInMethod($name, $this->driver($name));
    }

    /**
     * Register a sign-in method under the name, which must be lower case (a
     * letter, then letters, digits or underscores), so each method has one
     * spelling to be recorded and allowed under. The package's `password`
     * method cannot be replaced: `attempt()`, `validate()` and the rehash on a
     * password sign-in rely on it, so a replacement would change `signIn()` but
     * not them.
     *
     * @param  mixed  $driver
     * @param  \Closure  $callback
     * @return $this
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore missingType.callable
     */
    #[\Override]
    public function extend(mixed $driver, \Closure $callback): self
    {
        if (!is_string($driver) || preg_match(self::NAME_PATTERN, $driver) !== 1) {
            throw new \InvalidArgumentException('A sign-in method name must be lower case: a letter, then letters, digits or underscores.');
        }

        if ($driver === PasswordSignIn::NAME) {
            $message = sprintf('The [%s] sign-in method is the package\'s own and cannot be replaced; register yours under another name.', PasswordSignIn::NAME);

            throw new \InvalidArgumentException($message);
        }

        parent::extend($driver, $callback);

        return $this;
    }

    /**
     * Refuse to pick a method: every sign-in names the one it uses.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function getDefaultDriver(): string
    {
        throw new \InvalidArgumentException('Sign-in methods have no default; name the method to use.');
    }

    /**
     * Build the method registered under exactly the name: the package's
     * `password`, or one registered with `extend()`. Any other spelling,
     * including one that differs only in case or punctuation from a registered
     * name, is unknown.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    protected function createDriver(mixed $driver): mixed
    {
        if ($driver !== PasswordSignIn::NAME && !(is_string($driver) && array_key_exists($driver, $this->customCreators))) {
            throw new \InvalidArgumentException(sprintf('Sign-in method [%s] is not registered.', is_string($driver) ? $driver : get_debug_type($driver)));
        }

        return parent::createDriver($driver);
    }

    /**
     * Build the password sign-in method.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn
     */
    protected function createPasswordDriver(): PasswordSignIn
    {
        return new PasswordSignIn($this->config);
    }

    /**
     * Return what the name resolved to when it is a sign-in method.
     *
     * @param  string  $name
     * @param  mixed  $method
     * @return \SineMacula\Laravel\Authentication\Contracts\SignInMethod
     *
     * @throws \LogicException
     */
    private static function assertSignInMethod(string $name, mixed $method): SignInMethod
    {
        if (!$method instanceof SignInMethod) {
            throw new \LogicException(sprintf('Sign-in method [%s] resolved to %s, which does not implement %s.', $name, get_debug_type($method), SignInMethod::class));
        }

        return $method;
    }
}
