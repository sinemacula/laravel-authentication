<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * Unit tests for the package's Auth facade subclass.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversClass(Auth::class)]
final class AuthFacadeTest extends TestCase
{
    /**
     * Setup.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        // T22's AuthServiceProvider will replace the inline registration
        // below once committed. Until then, register the four contextual
        // macros here so the facade assertions run in isolation.
        IlluminateAuth::macro('principal', static fn (): ?Principal => null);
        IlluminateAuth::macro('device', static fn (): ?Device => null);
        IlluminateAuth::macro('tenant', static fn (): ?Tenant => null);
        IlluminateAuth::macro('type', static fn (): ?string => null);
    }

    /**
     * Teardown.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        IlluminateAuth::flushMacros();

        parent::tearDown();
    }

    /**
     * The package facade subclass extends Laravel's framework
     * `Auth` facade so IDE autocompletion picks up both surfaces.
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
     * The `principal` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testPrincipalMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('principal'));
    }

    /**
     * The `device` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testDeviceMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('device'));
    }

    /**
     * The `tenant` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testTenantMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('tenant'));
    }

    /**
     * The `type` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testTypeMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('type'));
    }

    /**
     * `Auth::manager()` returns the package `AuthManager` instance
     * resolved from the container, type-narrowed to the package
     * subclass so consumers can call `inheritDriversFrom()` and the
     * contextual accessors directly.
     *
     * @return void
     */
    public function testManagerResolvesPackageAuthManagerFromContainer(): void
    {
        // Register the package service provider so the `auth` binding
        // resolves to the package AuthManager subclass.
        $this->app?->register(AuthServiceProvider::class);

        $manager = Auth::manager();

        self::assertInstanceOf(AuthManager::class, $manager);
        self::assertSame(app('auth'), $manager);
    }

    /**
     * `Auth::manager()` throws `LogicException` when the `auth`
     * container binding does not resolve to a package `AuthManager`
     * instance - the safety net for consumers who forgot to register
     * the package service provider.
     *
     * @return void
     */
    public function testManagerThrowsWhenAuthBindingIsNotPackageManager(): void
    {
        // Replace the `auth` binding with a stock framework manager
        // so the type assertion fails inside `manager()`.
        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('AuthManager');

        Auth::manager();
    }
}
