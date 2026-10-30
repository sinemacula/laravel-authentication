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
 * Boots the package service provider so the `auth` binding resolves to the
 * package `AuthManager` subclass, then verifies the facade's structural
 * inheritance and the `manager()` type-narrowing accessor.
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
     * The package facade subclass extends Laravel's framework `Auth` facade so
     * IDE autocompletion picks up both surfaces.
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
     * The contextual accessors (`principal`, `device`, `tenant`, `type`) and
     * `sessions()` are real instance methods on the package `AuthManager` - not
     * macros. Verify they exist on the resolved manager so a rename or removal
     * fails the suite.
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
        self::assertTrue($reflection->hasMethod('device'));
        self::assertTrue($reflection->hasMethod('tenant'));
        self::assertTrue($reflection->hasMethod('type'));
        self::assertTrue($reflection->hasMethod('sessions'));
    }

    /**
     * `Auth::manager()` returns the package `AuthManager` instance resolved
     * from the container, type-narrowed to the package subclass so consumers
     * can call `inheritDriversFrom()` and the contextual accessors directly.
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
     * `Auth::manager()` throws `LogicException` when the `auth` container
     * binding does not resolve to a package `AuthManager` instance - the safety
     * net for consumers who forgot to register the package service provider.
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
     * `Auth::manager()` throws the same `LogicException` when the facades have
     * no application to resolve the binding from.
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
     * The facade annotates every public method the package `AuthManager`
     * declares, with the method's parameters and the return type its own
     * docblock states, so an IDE and static analysis see what a call takes and
     * returns: no method is missing, none is left over, and none says it may
     * return `null` when it never does.
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
     * Register the package service provider so the `auth` binding resolves to
     * the package `AuthManager` subclass.
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
     * name: its return type and its parameter list.
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
     * The signature a manager method declares, in the facade's notation: the
     * return type its docblock states (`?T` written `T|null`) and its
     * parameters with their types and defaults.
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
