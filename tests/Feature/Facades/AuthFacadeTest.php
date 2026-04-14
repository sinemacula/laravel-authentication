<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
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
     * The contextual accessors (`principal`, `device`, `tenant`, `type`) are
     * real instance methods on the package `AuthManager` - not macros. Verify
     * they exist on the resolved manager so a rename or removal fails the
     * suite.
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
    }

    /**
     * `Auth::manager()` returns the package `AuthManager` instance resolved
     * from the container, type-narrowed to the package subclass so consumers
     * can call `inheritDriversFrom()` and the contextual accessors directly.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testManagerResolvesPackageAuthManagerFromContainer(): void
    {
        $manager = Auth::manager();

        self::assertInstanceOf(AuthManager::class, $manager);
        self::assertSame(app('auth'), $manager);
    }

    /**
     * `Auth::manager()` throws `LogicException` when the `auth` container
     * binding does not resolve to a package `AuthManager` instance - the
     * safety net for consumers who forgot to register the package service
     * provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testManagerThrowsWhenAuthBindingIsNotPackageManager(): void
    {
        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('AuthManager');

        Auth::manager();
    }

    /**
     * Register the package service provider so the `auth` binding resolves to
     * the package `AuthManager` subclass.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthServiceProvider::class];
    }
}
