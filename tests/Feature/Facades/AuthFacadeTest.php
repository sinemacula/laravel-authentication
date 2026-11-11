<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * Feature tests for the package Auth facade.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversClass(Auth::class)]
final class AuthFacadeTest extends TestCase
{
    /** @var string The message for an `auth` binding that is not the package manager. */
    private const string UNREGISTERED_MESSAGE = 'The `auth` container binding did not resolve to an AuthManager instance'
        . ' - check that AuthenticationServiceProvider is registered.';

    /**
     * The package facade extends Laravel's `Auth` facade.
     *
     * @return void
     */
    public function testPackageFacadeExtendsFrameworkFacade(): void
    {
        $reflection = new \ReflectionClass(Auth::class);

        self::assertTrue(
            $reflection->isSubclassOf(IlluminateAuth::class),
            'Package Auth facade must extend Illuminate\Support\Facades\Auth.',
        );
    }

    /**
     * The contextual accessors are instance methods on the package
     * `AuthManager`.
     *
     * @return void
     */
    public function testContextualAccessorsAreInstanceMethodsNotMacros(): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertInstanceOf(AuthManager::class, $manager);

        $reflection = new \ReflectionClass($manager);

        self::assertTrue($reflection->hasMethod('principal'));
        self::assertTrue($reflection->hasMethod('session'));
        self::assertTrue($reflection->hasMethod('tenant'));
        self::assertFalse($reflection->hasMethod('type'));
        self::assertTrue($reflection->hasMethod('sessions'));
    }

    /**
     * `Auth::manager()` returns the package `AuthManager` from the container.
     *
     * @return void
     */
    public function testManagerResolvesPackageAuthManagerFromContainer(): void
    {
        $manager = Auth::manager();

        self::assertInstanceOf(AuthManager::class, $manager);
        self::assertSame(app('auth'), $manager);
    }

    /**
     * `Auth::manager()` throws when the `auth` binding is not the package
     * `AuthManager`.
     *
     * @return void
     */
    public function testManagerThrowsWhenAuthBindingIsNotPackageManager(): void
    {
        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::UNREGISTERED_MESSAGE);

        Auth::manager();
    }

    /**
     * `Auth::manager()` throws when the facades have no application.
     *
     * @return void
     */
    public function testManagerThrowsWhenTheFacadesHaveNoApplication(): void
    {
        $application = Auth::getFacadeApplication();

        Auth::setFacadeApplication(null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::UNREGISTERED_MESSAGE);

        try {
            Auth::manager();
        } finally {
            Auth::setFacadeApplication($application);
        }
    }

    /**
     * The facade annotates every public `AuthManager` method with its declared
     * parameters and return type.
     *
     * @return void
     */
    public function testTheFacadeAnnotatesEveryManagerMethodAsDeclared(): void
    {
        $declared = [];

        foreach ((new \ReflectionClass(AuthManager::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->getDeclaringClass()->getName() !== AuthManager::class) {
                continue;
            }

            $declared[$method->getName()] = self::declaredSignature($method);
        }

        $annotated = self::annotatedSignatures();

        ksort($declared);
        ksort($annotated);

        self::assertSame($declared, $annotated);
    }

    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }

    /**
     * The signature each `@method` annotation on the facade gives, by method
     * name.
     *
     * @return array<string, string>
     */
    private static function annotatedSignatures(): array
    {
        preg_match_all('/@method static (\S+) (\w+)\(([^)]*)\)/', (string) (new \ReflectionClass(Auth::class))->getDocComment(), $matches, PREG_SET_ORDER);

        $signatures = [];

        foreach ($matches as [, $return, $name, $parameters]) {
            $signatures[$name] = $return . ' (' . $parameters . ')';
        }

        return $signatures;
    }

    /**
     * The signature a manager method declares, in the facade's notation.
     *
     * @param  \ReflectionMethod  $method
     * @return string
     */
    private static function declaredSignature(\ReflectionMethod $method): string
    {
        preg_match('/@return (\S+)/', (string) $method->getDocComment(), $match);

        $return     = $match[1] ?? '';
        $return     = str_starts_with($return, '?') ? substr($return, 1) . '|null' : $return;
        $parameters = [];

        foreach ($method->getParameters() as $parameter) {

            $type = $parameter->getType();

            assert($type instanceof \ReflectionNamedType);

            $name    = $type->isBuiltin() ? $type->getName() : '\\' . $type->getName();
            $default = $parameter->isDefaultValueAvailable() ? ' = ' . strtolower(var_export($parameter->getDefaultValue(), true)) : '';

            $parameters[] = ($type->allowsNull() ? '?' : '') . $name . ' $' . $parameter->getName() . $default;
        }

        return $return . ' (' . implode(', ', $parameters) . ')';
    }
}
