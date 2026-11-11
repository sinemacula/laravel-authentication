<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The registry of sign-in methods, keyed by the name each is recorded under and
 * allowed by.
 *
 * A singleton that keeps each method it builds while the same application
 * serves, so methods must be stateless.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SignInMethodManager extends Manager
{
    /** @var list<string> Credential kinds an application may list in `methods` that are not sign-in methods; `extend()` refuses them. */
    public const array CREDENTIAL_METHODS = ['api_key', 'client_credentials'];

    /** @var string The method a session an external identity provider established records; `extend()` refuses it. */
    public const string EXTERNAL_METHOD = 'external_provider';

    /** @var string Pattern a registered method's name must match. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]*$/D';

    /** @var list<string> Methods the package registers itself; `extend()` refuses them. */
    private const array PACKAGE_METHODS = [PasswordSignIn::NAME, 'phone_code', 'email_code', 'passkey'];

    /** @var bool Whether the manager follows the application serving: it was built with the one then serving and given no container since. */
    private bool $followsApplication;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(ContainerContract $container)
    {
        parent::__construct($container);

        $this->followsApplication = $container === Container::getInstance();
    }

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
     * The names sign-in methods are registered under: the package's own, then
     * those registered with `extend()`.
     *
     * @return list<string>
     */
    public function names(): array
    {
        /** @var list<string> $registered */
        $registered = array_keys($this->customCreators);

        return [...self::PACKAGE_METHODS, ...$registered];
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
     * Register a sign-in method under a lower-case name; the package's own
     * names and the reserved credential kinds are refused.
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

        if ($driver === self::EXTERNAL_METHOD) {
            $message = sprintf('[%s] is the method external sign-ins are recorded under, not a sign-in method; register yours under another name.', $driver);

            throw new \InvalidArgumentException($message);
        }

        parent::extend($driver, $callback);

        return $this;
    }

    /**
     * Return the method registered under the name, built with the application
     * now serving unless the manager was given a container of its own.
     *
     * Under Octane a manager resolved at boot would otherwise build every
     * method with the booted application for the life of the worker.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function driver(mixed $driver = null): mixed
    {
        if ($driver !== null && !is_string($driver) && !$driver instanceof \UnitEnum) {
            throw new \InvalidArgumentException(sprintf('A sign-in method is named by a string or an enum case, not %s.', get_debug_type($driver)));
        }

        $current = Container::getInstance();

        if ($this->followsApplication && $current !== $this->container) {
            $this->container = $current;
            $this->config    = $current->make('config');
            $this->drivers   = [];
        }

        return parent::driver($driver);
    }

    /**
     * Build the methods with the container given from now on, whichever
     * application is serving.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return $this
     */
    #[\Override]
    public function setContainer(ContainerContract $container): self
    {
        $this->followsApplication = false;

        return parent::setContainer($container);
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
     * Build the method registered under exactly the name; any other spelling is
     * unknown.
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
     * Build the email address one-time code sign-in method.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSignIn
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createEmailCodeDriver(): CodeSignIn
    {
        return $this->container->make(CodeSignIn::class, ['type' => 'email']);
    }

    /**
     * Build the passkey sign-in method.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn
     */
    protected function createPasskeyDriver(): PasskeySignIn
    {
        return new PasskeySignIn($this->container);
    }

    /**
     * Whether a method is registered under exactly the name: one of the
     * package's own, or one registered with `extend()`.
     *
     * @param  string  $name
     * @return bool
     */
    private function isRegistered(string $name): bool
    {
        return array_key_exists($name, $this->customCreators) || in_array($name, self::PACKAGE_METHODS, true);
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
