<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Support\Manager;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The registry of sign-in methods, keyed by the name each is recorded under on
 * the devices it signs in and allowed under in a guard's audience policy.
 *
 * The package registers its own methods (`password`, which `attempt()` and
 * `validate()` also use directly, `phone_code`, `email_code` and `passkey`), so
 * their names are reserved: `extend('password', ...)` throws. So are the
 * machine credential kinds an audience may list beside them (`api_key`,
 * `client_credentials`), which are not sign-in methods and never resolve to
 * one. Other methods register themselves with `extend()` under a lower-case
 * name (a letter, then letters, digits or underscores), for example from a
 * service provider:
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
    /** @var list<string> Credential kinds an audience may list in `methods` that are not sign-in methods; `extend()` refuses them. */
    public const array CREDENTIAL_METHODS = ['api_key', 'client_credentials'];

    /** @var string Pattern a registered method's name must match. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]*$/D';

    /** @var list<string> Methods the package registers itself; `extend()` refuses them. */
    private const array PACKAGE_METHODS = [PasswordSignIn::NAME, 'phone_code', 'email_code', 'passkey'];

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
     * Whether the name is one a sign-in method can be registered under: a
     * lower-case letter, then lower-case letters, digits or underscores.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isValidName(string $name): bool
    {
        return preg_match(self::NAME_PATTERN, $name) === 1;
    }

    /**
     * Register a sign-in method under the name, which must be lower case (a
     * letter, then letters, digits or underscores), so each method has one
     * spelling to be recorded and allowed under. The package's own methods
     * cannot be replaced: `attempt()`, `validate()` and the rehash on a
     * password sign-in rely on `password`, so a replacement would change
     * `signIn()` but not them, and the others hold the package's guarantees for
     * codes and passkeys. The machine credential kinds cannot be registered
     * either, since an audience that lists one allows a credential, not a
     * sign-in.
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
        if (!is_string($driver) || !self::isValidName($driver)) {
            throw new \InvalidArgumentException('A sign-in method name must be lower case: a letter, then letters, digits or underscores.');
        }

        if (in_array($driver, self::PACKAGE_METHODS, true)) {
            $message = sprintf('The [%s] sign-in method is the package\'s own and cannot be replaced; register yours under another name.', $driver);

            throw new \InvalidArgumentException($message);
        }

        if (in_array($driver, self::CREDENTIAL_METHODS, true)) {
            $message = sprintf('[%s] names a machine credential, not a sign-in method; register yours under another name.', $driver);

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
     * Build the method registered under exactly the name: one of the package's
     * own, through its `create<Name>Driver()` method, or one registered with
     * `extend()`. Any other spelling, including one that differs only in case
     * or punctuation from a registered name, is unknown, as is a package name
     * whose creator is not defined.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    protected function createDriver(mixed $driver): mixed
    {
        if (!is_string($driver) || !$this->isRegistered($driver)) {
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
     * Build the phone number one-time code sign-in method.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSignIn
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createPhoneCodeDriver(): CodeSignIn
    {
        return $this->container->make(CodeSignIn::class, ['type' => 'phone']);
    }

    /**
     * Whether a method is registered under exactly the name: a package method
     * whose creator is defined, or one registered with `extend()`.
     *
     * @param  string  $name
     * @return bool
     */
    private function isRegistered(string $name): bool
    {
        if (array_key_exists($name, $this->customCreators)) {
            return true;
        }

        return in_array($name, self::PACKAGE_METHODS, true) && method_exists($this, 'create' . Str::studly($name) . 'Driver');
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
