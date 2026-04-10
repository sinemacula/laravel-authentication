<?php

declare(strict_types = 1);

namespace Tests\Integration\Facade;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Factory as IlluminateAuthFactoryContract;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth as IlluminateAuth;
use Tests\TestCase;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration test for the Auth facade contextual macros.
 *
 * Boots the package service provider through Testbench and asserts that the
 * four contextual `Auth::...()` macros (`principal`, `device`, `tenant`,
 * `type`) return resolved values when the active guard implements
 * `ContextualGuard` and a user is bound, and return `null` when the guard is
 * unauthenticated or does not implement `ContextualGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(IlluminateAuth::class)]
#[CoversClass(AuthServiceProvider::class)]
#[CoversClass(AuthManager::class)]
final class AuthFacadeMacroIntegrationTest extends TestCase
{
    /**
     * `Auth::principal()` returns null for an unauthenticated request when the
     * default guard is the package's `api` jwt guard.
     *
     * @return void
     */
    public function testAuthPrincipalReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertInstanceOf(ContextualGuard::class, IlluminateAuth::guard('api'));

        self::assertNull(IlluminateAuth::principal());
    }

    /**
     * `Auth::device()` returns null for an unauthenticated request.
     *
     * @return void
     */
    public function testAuthDeviceReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertNull(IlluminateAuth::device());
    }

    /**
     * `Auth::tenant()` returns null for an unauthenticated request.
     *
     * @return void
     */
    public function testAuthTenantReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertNull(IlluminateAuth::tenant());
    }

    /**
     * `Auth::type()` returns null for an unauthenticated request.
     *
     * @return void
     */
    public function testAuthTypeReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertNull(IlluminateAuth::type());
    }

    /**
     * After binding an identity + principal via the contextual guard's
     * `login()`, `Auth::principal()` forwards to the guard and returns the
     * resolved principal.
     *
     * @return void
     */
    public function testAuthPrincipalForwardsToContextualGuardWhenAuthenticated(): void
    {
        $principal = $this->loginThroughContextualGuard();

        /** @var \SineMacula\Laravel\Authentication\Contracts\Principal|null $resolved */
        $resolved = IlluminateAuth::principal();

        self::assertSame($principal, $resolved);
    }

    /**
     * After `login()` with a bound device, `Auth::device()` forwards to the
     * contextual guard and returns the bound device.
     *
     * @return void
     */
    public function testAuthDeviceForwardsToContextualGuardWhenAuthenticated(): void
    {
        $device = new StubDevice;
        $device->forceFill([
            'id'          => '019590e0-0000-7000-8000-000000000001',
            'os'          => 'ios',
            'refresh_key' => 'rk',
        ]);

        $this->loginThroughContextualGuard($device);

        /** @var \SineMacula\Laravel\Authentication\Contracts\Device|null $resolved */
        $resolved = IlluminateAuth::device();

        self::assertSame($device, $resolved);
    }

    /**
     * When the default guard is swapped to a stock framework guard (the
     * session `web` guard) the macro returns the safe fallback because the
     * resolved guard does not implement `ContextualGuard`.
     *
     * @return void
     */
    public function testAuthFallbackForNonContextualGuard(): void
    {
        config()->set('auth.defaults.guard', 'web');

        // Force the auth factory to forget any cached guard so the next resolve
        // returns the newly-defaulted web guard.
        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth = app(IlluminateAuthFactoryContract::class);
        $auth->forgetGuards();

        $guard = IlluminateAuth::guard();

        self::assertNotInstanceOf(ContextualGuard::class, $guard);

        self::assertNull(IlluminateAuth::principal());
        self::assertNull(IlluminateAuth::device());
        self::assertNull(IlluminateAuth::tenant());
        self::assertNull(IlluminateAuth::type());
    }

    /**
     * Configure two guards: the package `api` guard (jwt driver) and a stock
     * framework `web` guard (session driver). Individual tests flip the
     * default guard between them to exercise both branches of the macro's
     * `ContextualGuard` check.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.defaults.passwords', 'users');

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.web', [
            'driver'   => 'session',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Bind a `StubPrincipal` (and optional `StubDevice`) to the active
     * contextual guard via the package's `login()` surface so the macro
     * assertions observe a fully-resolved context.
     *
     * @param  \Tests\Unit\Stubs\StubDevice|null  $device
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function loginThroughContextualGuard(?StubDevice $device = null): StubPrincipal
    {
        $principal = new StubPrincipal;
        $principal->forceFill([
            'id'        => 1,
            'is_active' => true,
        ]);

        $guard = IlluminateAuth::guard('api');

        self::assertInstanceOf(ContextualGuard::class, $guard);

        $guard->login($principal, $principal, $device);

        return $principal;
    }
}
