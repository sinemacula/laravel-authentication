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
 * The package registers `password`. Other methods register themselves with
 * `extend()`, for example from a service provider:
 *
 * `$app->make(SignInMethodManager::class)->extend('sso', fn ($app) => $app->make(SsoSignIn::class));`
 *
 * A singleton that keeps each method it builds for the life of the process,
 * which is why methods must be stateless. There is no default method: every
 * sign-in names the method it uses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SignInMethodManager extends Manager
{
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
     * Build the password sign-in method.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn
     */
    protected function createPasswordDriver(): PasswordSignIn
    {
        return new PasswordSignIn($this->config, $this->container);
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
