<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use Tests\TestCase;

/**
 * Feature tests for the sign-in method registry: the container binding, the
 * built-in password method, methods registered with `extend()`, and the
 * refusals for a method that is unknown, not a sign-in method, or not named.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInMethodManager::class)]
final class SignInMethodManagerTest extends TestCase
{
    /**
     * The registry is a container singleton, and it keeps the password method
     * it built, reading the identifier key from the configuration on each call.
     *
     * @return void
     */
    public function testIsASingletonThatBuildsThePasswordMethodOnce(): void
    {
        $manager = $this->manager();

        self::assertSame($manager, $this->manager());

        $password = $manager->method('password');

        self::assertInstanceOf(PasswordSignIn::class, $password);
        self::assertSame($password, $manager->method('password'));
        self::assertSame('email', $password->identifierType('api'));

        config()->set('authentication.sign_in.password_identifier', 'username');

        self::assertSame('username', $password->identifierType('api'));
    }

    /**
     * A method registered with `extend()` is built from the container under its
     * name.
     *
     * @return void
     */
    public function testExtendRegistersAMethodUnderItsName(): void
    {
        $sso = new class implements SignInMethod {
            /**
             * No identifier.
             *
             * @param  string  $guard
             * @return ?string
             */
            #[\Override]
            public function identifierType(string $guard): ?string
            {
                unset($guard);

                return null;
            }

            /**
             * No identifier.
             *
             * @param  string  $guard
             * @param  array<array-key, mixed>  $input
             * @return ?string
             */
            #[\Override]
            public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string
            {
                unset($guard, $input);

                return null;
            }

            /**
             * Never verifies.
             *
             * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
             * @return \SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
             */
            #[\Override]
            public function authenticate(SignInRequest $request): SignInFailureReason
            {
                return SignInFailureReason::INVALID_CREDENTIALS;
            }
        };

        $received = null;

        $this->manager()->extend('sso', function (Application $app) use ($sso, &$received): SignInMethod {
            $received = $app;

            return $sso;
        });

        self::assertSame($sso, $this->manager()->method('sso'));
        self::assertSame($this->app, $received);
    }

    /**
     * The package's `password` method cannot be replaced, since `attempt()` and
     * `validate()` use it directly; the manager still builds the shipped one.
     *
     * @return void
     */
    public function testThePasswordMethodCannotBeReplaced(): void
    {
        $manager = $this->manager();

        try {
            $manager->extend('password', fn (): mixed => null);

            self::fail('Expected the password method to be reserved.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The [password] sign-in method is the package\'s own and cannot be replaced; register yours under another name.', $exception->getMessage());
        }

        self::assertInstanceOf(PasswordSignIn::class, $manager->method('password'));
        self::assertSame($manager, $manager->extend('passkey', fn (): mixed => null));
    }

    /**
     * An unknown method name fails as a misconfiguration.
     *
     * @return void
     */
    public function testRejectsAnUnknownMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Driver [carrier-pigeon] not supported.');

        $this->manager()->method('carrier-pigeon');
    }

    /**
     * A registered method that does not implement `SignInMethod` fails as a
     * misconfiguration naming the method and what it resolved to.
     *
     * @return void
     */
    public function testRejectsAMethodThatIsNotASignInMethod(): void
    {
        $this->manager()->extend('broken', fn (): \stdClass => new \stdClass);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Sign-in method [broken] resolved to stdClass, which does not implement ' . SignInMethod::class . '.');

        $this->manager()->method('broken');
    }

    /**
     * There is no default method: asking for one fails rather than signing in
     * with a method nobody named.
     *
     * @return void
     */
    public function testHasNoDefaultMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Sign-in methods have no default; name the method to use.');

        $this->manager()->driver();
    }

    /**
     * Resolve the registry from the container.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInMethodManager
     */
    private function manager(): SignInMethodManager
    {
        return app(SignInMethodManager::class);
    }
}
