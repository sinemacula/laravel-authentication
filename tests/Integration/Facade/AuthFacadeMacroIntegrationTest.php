<?php

declare(strict_types = 1);

namespace Tests\Integration\Facade;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Factory as IlluminateAuthFactoryContract;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ReadsActiveGuard;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth as IlluminateAuth;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubSession;

/**
 * Integration tests for the Auth facade's contextual macros.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IlluminateAuth::class)]
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(AuthManager::class)]
#[CoversTrait(ReadsActiveGuard::class)]
final class AuthFacadeMacroIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /**
     * `Auth::principal()` returns null for an unauthenticated request.
     *
     * @return void
     */
    public function testAuthPrincipalReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertInstanceOf(ContextualGuard::class, IlluminateAuth::guard('api'));

        self::assertNull(IlluminateAuth::principal());
    }

    /**
     * `Auth::session()` returns null for an unauthenticated request.
     *
     * @return void
     */
    public function testAuthSessionReturnsNullForUnauthenticatedRequest(): void
    {
        self::assertNull(IlluminateAuth::session());
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
     * `Auth::principal()` returns the principal the contextual guard bound.
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
     * `Auth::session()` returns the session the contextual guard bound.
     *
     * @return void
     */
    public function testAuthSessionForwardsToContextualGuardWhenAuthenticated(): void
    {
        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(),
            'id'          => '019590e0-0000-7000-8000-000000000001',
            'refresh_key' => 'rk',
        ]);

        $this->loginThroughContextualGuard($session);

        /** @var \SineMacula\Laravel\Authentication\Contracts\Session|null $resolved */
        $resolved = IlluminateAuth::session();

        self::assertSame($session, $resolved);
    }

    /**
     * A guard that is not contextual gets the macro's fallback.
     *
     * @return void
     */
    public function testAuthFallbackForNonContextualGuard(): void
    {
        config()->set('auth.defaults.guard', 'web');

        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth = app(IlluminateAuthFactoryContract::class);
        $auth->forgetGuards();

        $guard = IlluminateAuth::guard();

        self::assertNotInstanceOf(ContextualGuard::class, $guard);

        self::assertNull(IlluminateAuth::principal());
        self::assertNull(IlluminateAuth::session());
        self::assertNull(IlluminateAuth::tenant());
    }

    /**
     * Configure the package's `api` guard and a stock `web` guard.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

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
     * Log a `StubPrincipal`, and the session if given, in through the
     * contextual guard.
     *
     * @param  \Tests\Unit\Stubs\StubSession|null  $session
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function loginThroughContextualGuard(?StubSession $session = null): StubPrincipal
    {
        $principal = new StubPrincipal;
        $principal->forceFill([
            'id'        => 1,
            'is_active' => true,
        ]);

        $guard = IlluminateAuth::guard('api');

        self::assertInstanceOf(ContextualGuard::class, $guard);

        $guard->login($principal, $principal, $session);

        return $principal;
    }
}
