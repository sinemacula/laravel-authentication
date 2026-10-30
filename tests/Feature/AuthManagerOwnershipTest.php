<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\RequestGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Gate;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Fixtures\Providers\EarlyAuthProvider;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the package's ownership of the `auth` binding when another
 * package used Laravel's manager before the package booted: the drivers, the
 * user resolver and the resolved guards it left on that manager are the package
 * manager's, and the facades reach the package manager.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(AuthManager::class)]
final class AuthManagerOwnershipTest extends TestCase
{
    /**
     * The container, Laravel's facade and the package's facade all reach the
     * package's manager, though the facade resolved Laravel's before the
     * package booted, and the package's guard driver is registered on it.
     *
     * @return void
     */
    public function testTheContainerAndTheFacadesReachThePackagesManager(): void
    {
        $manager = app('auth');

        self::assertInstanceOf(AuthManager::class, $manager);
        self::assertSame($manager, IlluminateAuth::getFacadeRoot());
        self::assertSame($manager, Auth::getFacadeRoot());
        self::assertInstanceOf(JwtGuard::class, $manager->guard('api'));
    }

    /**
     * A guard driver and a user provider driver registered on Laravel's manager
     * before the package booted build guards through the package's manager.
     *
     * @return void
     */
    public function testDriversRegisteredBeforeThePackageBootedBuildItsGuards(): void
    {
        $guard = app('auth')->guard('early_other');

        self::assertInstanceOf(RequestGuard::class, $guard);
        self::assertInstanceOf(EloquentUserProvider::class, $guard->getProvider());
        self::assertNotSame(app('auth')->guard('early_guard'), $guard);
    }

    /**
     * A request guard registered with `viaRequest()` before the package booted
     * takes its user provider from the package's manager, through a driver
     * (`model`) registered only after the manager was replaced.
     *
     * @return void
     */
    public function testARequestGuardRegisteredBeforeThePackageBootedTakesAProviderRegisteredAfter(): void
    {
        $guard = app('auth')->guard('early_request_guard');

        self::assertInstanceOf(RequestGuard::class, $guard);
        self::assertInstanceOf(ModelProvider::class, $guard->getProvider());
    }

    /**
     * The default guard, resolved before the package booted, is the one the
     * package's manager returns and the one `auth.driver` holds, and it still
     * receives each new request.
     *
     * @return void
     *
     * @throws \Illuminate\Container\EntryNotFoundException
     * @throws \Illuminate\Contracts\Container\CircularDependencyException
     */
    public function testAGuardResolvedBeforeThePackageBootedIsTheSameInstance(): void
    {
        $guard = app('auth')->guard();

        self::assertInstanceOf(RequestGuard::class, $guard);
        self::assertSame($guard, app()->get('auth.driver'));
        self::assertSame($guard, app('auth')->guard('early_guard'));

        $request = Request::create('/next');

        app()->instance('request', $request);

        self::assertSame($request, (new \ReflectionProperty($guard, 'request'))->getValue($guard));
    }

    /**
     * The user resolver set with `resolveUsersUsing()` before the package
     * booted is the one the gate, the request and the `Authenticatable`
     * contract resolve the user through.
     *
     * @return void
     */
    public function testAUserResolverSetBeforeThePackageBootedResolvesTheUser(): void
    {
        Gate::define('early', static fn (Authenticatable $user): bool => $user->getAuthIdentifier() === EarlyAuthProvider::USER);

        app()->instance('request', Request::create('/'));

        self::assertTrue(Gate::allows('early'));
        self::assertSame(EarlyAuthProvider::USER, app(Authenticatable::class)->getAuthIdentifier());
        self::assertSame(EarlyAuthProvider::USER, request()->user()?->getAuthIdentifier());
    }

    /**
     * Register the provider that uses Laravel's manager, then the package's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [EarlyAuthProvider::class, AuthenticationServiceProvider::class];
    }

    /**
     * Configure the early provider's guards, a request guard whose default
     * provider uses the package's `model` driver, and a JWT guard.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('authentication.jwt.keys', ['default' => 'test-secret-key-with-at-least-32-bytes!']);
        $config->set('authentication.jwt.active_kid', 'default');
        $config->set('authentication.jwt.algorithm', 'HS256');

        $config->set('auth.providers.early_users', ['driver' => 'early', 'model' => StubAuthenticatableModel::class]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubAuthenticatableModel::class]);
        $config->set('auth.defaults.provider', 'identities');
        $config->set('auth.defaults.guard', 'early_guard');
        $config->set('auth.guards.early_guard', ['driver' => 'early', 'provider' => 'early_users']);
        $config->set('auth.guards.early_other', ['driver' => 'early', 'provider' => 'early_users']);
        $config->set('auth.guards.early_request_guard', ['driver' => 'early_request']);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
    }
}
