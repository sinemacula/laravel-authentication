<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
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
             * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
             */
            #[\Override]
            public function authenticate(SignInRequest $request): FailureReason
            {
                return FailureReason::INVALID_CREDENTIALS;
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
        self::assertSame($manager, $manager->extend('magic_link', fn (): mixed => null));
    }

    /**
     * Rows of `[name, class]`: every method the package registers itself, and
     * the class it resolves to.
     *
     * @return iterable<string, array{0: string, 1: class-string<\SineMacula\Laravel\Authentication\Contracts\SignInMethod>}>
     */
    public static function providePackageMethodNames(): iterable
    {
        yield from [
            'password'   => ['password', PasswordSignIn::class],
            'phone code' => ['phone_code', CodeSignIn::class],
            'email code' => ['email_code', CodeSignIn::class],
            'passkey'    => ['passkey', PasskeySignIn::class],
        ];
    }

    /**
     * None of the package's own methods can be replaced through `extend()`, and
     * each resolves to the package's own method.
     *
     * @param  string  $name
     * @param  class-string<\SineMacula\Laravel\Authentication\Contracts\SignInMethod>  $class
     * @return void
     */
    #[DataProvider('providePackageMethodNames')]
    public function testThePackageMethodsAreReserved(string $name, string $class): void
    {
        $manager = $this->manager();

        try {
            $manager->extend($name, fn (): mixed => null);

            self::fail("Expected [{$name}] to be reserved.");
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("The [{$name}] sign-in method is the package's own and cannot be replaced; register yours under another name.", $exception->getMessage());
        }

        self::assertInstanceOf($class, $manager->method($name));
    }

    /**
     * Rows of `[name]`: the machine credential kinds an audience may list.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCredentialMethodNames(): iterable
    {
        yield from [
            'api key'            => ['api_key'],
            'client credentials' => ['client_credentials'],
        ];
    }

    /**
     * A machine credential kind is not a sign-in method: it cannot be
     * registered as one, and never resolves to one.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideCredentialMethodNames')]
    public function testTheCredentialKindsAreNotSignInMethods(string $name): void
    {
        $manager = $this->manager();

        self::assertContains($name, SignInMethodManager::CREDENTIAL_METHODS);

        try {
            $manager->extend($name, fn (): mixed => null);

            self::fail("Expected [{$name}] to be refused.");
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("[{$name}] names a machine credential, not a sign-in method; register yours under another name.", $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Sign-in method [{$name}] is not registered.");

        $manager->method($name);
    }

    /**
     * The credential kinds are exactly the two machine credentials.
     *
     * @return void
     */
    public function testTheCredentialKinds(): void
    {
        self::assertSame(['api_key', 'client_credentials'], SignInMethodManager::CREDENTIAL_METHODS);
    }

    /**
     * The registered names are the package's own methods, then those registered
     * with `extend()`, in the order they were registered, and no credential
     * kind.
     *
     * @return void
     */
    public function testNamesTheRegisteredMethods(): void
    {
        $manager = $this->manager();

        self::assertSame(['password', 'phone_code', 'email_code', 'passkey'], $manager->names());

        $manager->extend('whatsapp_code', fn (): SignInMethod => \Mockery::mock(SignInMethod::class));
        $manager->extend('sso', fn (): SignInMethod => \Mockery::mock(SignInMethod::class));

        self::assertSame(['password', 'phone_code', 'email_code', 'passkey', 'whatsapp_code', 'sso'], $manager->names());
    }

    /**
     * An unknown method name fails as a misconfiguration.
     *
     * @return void
     */
    public function testRejectsAnUnknownMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Sign-in method [carrier-pigeon] is not registered.');

        $this->manager()->method('carrier-pigeon');
    }

    /**
     * Rows of `[name]`: spellings of the registered `password` and `sso`
     * methods that differ in case, punctuation or spacing, which Laravel's
     * manager would otherwise resolve through the case-insensitive creator
     * method it builds from the name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherSpellingsOfRegisteredNames(): iterable
    {
        yield from [
            'upper case'     => ['PASSWORD'],
            'title case'     => ['Password'],
            'underscored'    => ['pass_word'],
            'hyphenated'     => ['pass-word'],
            'spaced'         => ['pass word'],
            'registered, up' => ['SSO'],
        ];
    }

    /**
     * A method resolves only by the exact name it was registered under, so a
     * guard cannot allow, and a device cannot record, a second spelling of one
     * method; `driver()` holds to the same rule as `method()`.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideOtherSpellingsOfRegisteredNames')]
    public function testResolvesOnlyTheExactNameAMethodWasRegisteredUnder(string $name): void
    {
        $manager = $this->manager();

        $manager->extend('sso', fn (): SignInMethod => $manager->method('password'));

        foreach ([static fn (): mixed => $manager->method($name), static fn (): mixed => $manager->driver($name)] as $resolve) {
            try {
                $resolve();

                self::fail("Expected [{$name}] to be unknown.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("Sign-in method [{$name}] is not registered.", $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[name]` that are not a lower-case method name.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedMethodNames(): iterable
    {
        yield from [
            'title case'       => ['Password'],
            'upper case'       => ['SSO'],
            'hyphenated'       => ['magic-link'],
            'leading digit'    => ['2fa'],
            'leading score'    => ['_sso'],
            'trailing newline' => ["sso\n"],
            'spaced'           => ['magic link'],
            'empty'            => [''],
            'not a string'     => [5],
        ];
    }

    /**
     * A method is registered only under a lower-case name, so every method has
     * exactly one spelling.
     *
     * @param  mixed  $name
     * @return void
     */
    #[DataProvider('provideMalformedMethodNames')]
    public function testExtendRefusesANameThatIsNotLowerCase(mixed $name): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A sign-in method name must be lower case: a letter, then letters, digits or underscores.');

        $this->manager()->extend($name, fn (): mixed => null);
    }

    /**
     * The name check the audience policy shares accepts exactly the names a
     * method can be registered under.
     *
     * @return void
     */
    public function testIsValidNameAcceptsOnlyRegistrableNames(): void
    {
        foreach (['password', 'sso', 'magic_link', 'totp2'] as $name) {
            self::assertTrue(SignInMethodManager::isValidName($name), $name);
        }

        foreach (['Password', 'SSO', 'magic-link', '2fa', '_sso', "sso\n", 'magic link', ''] as $name) {
            self::assertFalse(SignInMethodManager::isValidName($name), $name);
        }
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
