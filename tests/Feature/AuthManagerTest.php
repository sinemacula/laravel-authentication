<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the package AuthManager subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthManager::class)]
final class AuthManagerTest extends TestCase
{
    /**
     * The `auth` container binding resolves to the package `AuthManager`
     * subclass after the service provider boots.
     *
     * @return void
     */
    public function testAuthBindingResolvesToPackageAuthManager(): void
    {
        self::assertInstanceOf(AuthManager::class, app('auth'));
    }

    /**
     * The package `AuthManager` is a subclass of Laravel's framework
     * `AuthManager`.
     *
     * @return void
     */
    public function testAuthManagerExtendsLaravelAuthManager(): void
    {
        self::assertInstanceOf(IlluminateAuthManager::class, app('auth'));
    }

    /**
     * The package `AuthManager` exposes a concrete `jwt()` instance method that
     * resolves a guard-scoped `JwtTokenService`.
     *
     * @return void
     */
    public function testAuthManagerExposesJwtMethod(): void
    {
        $this->configureJwtGuard();

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertInstanceOf(JwtTokenService::class, $manager->jwt('test_jwt'));
    }

    /**
     * `sessions()` hands out the named JWT guard's own session service, or the
     * default guard's when no name is given.
     *
     * @return void
     */
    public function testSessionsReturnsTheJwtGuardsSessionService(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $guard   = $manager->guard('test_jwt');

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($guard->sessions(), $manager->sessions('test_jwt'));
        self::assertSame($guard->sessions(), $manager->sessions());
    }

    /**
     * `passkeys()` hands out a passkey service of the named JWT guard, or of
     * the default guard when no name is given; a guard that is not a JWT guard
     * has none, and asking for one names the guard.
     *
     * @return void
     */
    public function testPasskeysReturnsAJwtGuardsPasskeyService(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertInstanceOf(PasskeyService::class, $manager->passkeys('test_jwt'));
        self::assertInstanceOf(PasskeyService::class, $manager->passkeys());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no passkey service.');

        $manager->passkeys('web');
    }

    /**
     * A guard that is not a JWT guard has no session service, and asking for
     * one names the guard.
     *
     * @return void
     */
    public function testSessionsRejectsAGuardThatIsNotAJwtGuard(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        try {
            $manager->sessions();
            self::fail('Expected the session guard to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [web] is not a jwt guard, so it has no session service.', $exception->getMessage());
        }

        config()->set('auth.defaults.guard', 'test_jwt');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no session service.');

        $manager->sessions('web');
    }

    /**
     * `refreshTransport()` hands out the named JWT guard's transport, or the
     * default guard's, built from that guard's configuration.
     *
     * @return void
     */
    public function testRefreshTransportReadsWithTheJwtGuardsTransport(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');
        config()->set('auth.guards.test_jwt.refresh_token', ['sources' => ['header'], 'header' => 'X-Token']);

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $request = Request::create('/auth/refresh', 'POST', server: ['HTTP_X_TOKEN' => 'token']);

        $named = $manager->refreshTransport('test_jwt')->read($request);

        self::assertInstanceOf(PresentedRefreshToken::class, $named);
        self::assertSame(RefreshTokenSource::HEADER, $named->source);
        self::assertInstanceOf(PresentedRefreshToken::class, $manager->refreshTransport()->read($request));
    }

    /**
     * A guard that is not a JWT guard has no refresh token transport, and
     * asking for one names the guard.
     *
     * @return void
     */
    public function testRefreshTransportRejectsAGuardThatIsNotAJwtGuard(): void
    {
        $this->configureJwtGuard();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no refresh token transport.');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $manager->refreshTransport('web');
    }

    /**
     * `forgetGuardState()` resets each resolved package guard to the current
     * request, signed out, without recreating it, and leaves guards of other
     * drivers alone.
     *
     * @return void
     */
    public function testForgetGuardStateSignsThePackageGuardsOutOnTheCurrentRequest(): void
    {
        $this->configureJwtGuard();

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $session = \Mockery::mock(Guard::class);
        $session->shouldNotReceive('setRequest');

        $manager->extend('mocked', fn (): Guard => $session);
        config()->set('auth.guards.mocked', ['driver' => 'mocked']);

        // Another driver's guard resolved first, so the reset must pass it by.
        $manager->guard('mocked');

        $jwt = $manager->guard('test_jwt');

        self::assertInstanceOf(JwtGuard::class, $jwt);

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn(1);
        $principal->shouldReceive('getTenant')->andReturnNull();

        $request = Request::create('/next');

        app()->instance('request', $request);

        $jwt->setRequest(Request::create('/previous'));
        $jwt->login($identity, $principal);

        $manager->forgetGuardState();

        self::assertFalse($jwt->hasUser());
        self::assertNull($jwt->principal());
        self::assertSame($request, $jwt->getRequest());
        self::assertSame($jwt, $manager->guard('test_jwt'));
    }

    /**
     * `inheritStateFrom()` takes over the replaced manager's guard and user
     * provider creators, so guards and providers registered on it before the
     * package booted resolve through the package's manager.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromTakesOverTheCreators(): void
    {
        $donor = new IlluminateAuthManager(app());

        $guardInstance    = \Mockery::mock(Guard::class);
        $providerInstance = \Mockery::mock(UserProvider::class);

        $donor->extend('inherited-guard', fn (): Guard => $guardInstance);
        $donor->provider('inherited-provider', static fn (): UserProvider => $providerInstance);

        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom($donor);

        config()->set('auth.guards.inherited-guard-instance', [
            'driver'   => 'inherited-guard',
            'provider' => 'inherited-provider-instance',
        ]);
        config()->set('auth.providers.inherited-provider-instance', [
            'driver' => 'inherited-provider',
        ]);

        self::assertSame($guardInstance, $receiver->guard('inherited-guard-instance'));
        self::assertSame($providerInstance, $receiver->createUserProvider('inherited-provider-instance'));
    }

    /**
     * A creator bound to the replaced manager, as `viaRequest()` binds its own,
     * is bound to the package's manager instead: the request guard it builds
     * takes the user provider the package's manager creates, from a driver
     * registered only after the swap.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromBindsTheReplacedManagersCreatorsToTheNewManager(): void
    {
        $donor = new IlluminateAuthManager(app());
        $donor->viaRequest('donor-request', fn (): null => null);

        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom($donor);

        $provider = \Mockery::mock(UserProvider::class);

        $receiver->provider('registered-after', static fn (): UserProvider => $provider);

        config()->set('auth.providers.late', ['driver' => 'registered-after']);
        config()->set('auth.defaults.provider', 'late');
        config()->set('auth.guards.donor-request-guard', ['driver' => 'donor-request']);

        $guard = $receiver->guard('donor-request-guard');

        self::assertInstanceOf(RequestGuard::class, $guard);
        self::assertSame($provider, $guard->getProvider());
    }

    /**
     * A user provider creator bound to the replaced manager is bound to the
     * package's manager too: one that builds its provider from another of the
     * manager's providers reaches a driver registered only after the swap.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromBindsTheReplacedManagersProviderCreatorsToTheNewManager(): void
    {
        $donor     = new IlluminateAuthManager(app());
        $delegates = \Closure::bind(fn (): ?UserProvider => $this->createUserProvider('late'), $donor, IlluminateAuthManager::class);

        self::assertNotNull($delegates);

        $donor->provider('delegating', $delegates);

        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom($donor);

        $provider = \Mockery::mock(UserProvider::class);

        $receiver->provider('registered-after', static fn (): UserProvider => $provider);

        config()->set('auth.providers.late', ['driver' => 'registered-after']);
        config()->set('auth.providers.delegating-instance', ['driver' => 'delegating']);

        self::assertSame($provider, $receiver->createUserProvider('delegating-instance'));
    }

    /**
     * A closure bound to anything but the replaced manager is taken as it is,
     * and so is a first-class callable of the replaced manager's own method,
     * which keeps the object whose method it is.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromTakesOtherClosuresAsTheyAre(): void
    {
        $donor    = new IlluminateAuthManager(app());
        $owner    = new \ArrayObject;
        $resolver = (fn (): null => null)->bindTo($owner);

        self::assertNotNull($resolver);

        $donor->extend('method', $donor->createSessionDriver(...));
        $donor->resolveUsersUsing($resolver);

        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom($donor);

        $creators = self::readProperty($receiver, 'customCreators');

        self::assertIsArray($creators);
        self::assertInstanceOf(\Closure::class, $creators['method']);
        self::assertSame($donor, (new \ReflectionFunction($creators['method']))->getClosureThis());
        self::assertSame($resolver, $receiver->userResolver());
    }

    /**
     * The replaced manager's default user resolver, bound to it, is bound to
     * the package's manager, so the user resolves through the package's guards;
     * so is the one `shouldUse()` sets.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromBindsTheReplacedManagersUserResolverToTheNewManager(): void
    {
        $user = new GenericUser(['id' => 'resolved']);

        foreach ([false, true] as $switched) {

            $donor = new IlluminateAuthManager(app());

            if ($switched) {
                $donor->shouldUse('resolving');
            }

            $receiver = new AuthManager(app());
            $receiver->inheritStateFrom($donor);

            $guard = \Mockery::mock(Guard::class);
            $guard->shouldReceive('user')->andReturn($user);

            $receiver->extend('resolving', fn (): Guard => $guard);

            config()->set('auth.guards.resolving', ['driver' => 'resolving']);
            config()->set('auth.defaults.guard', 'resolving');

            self::assertSame($user, ($receiver->userResolver())());
        }
    }

    /**
     * A user resolver set on the replaced manager with `resolveUsersUsing()`,
     * here a static closure, bound to nothing, is the package manager's.
     *
     * @return void
     */
    public function testInheritStateFromTakesOverACustomUserResolver(): void
    {
        $resolver = static fn (): GenericUser => new GenericUser(['id' => 'custom']);

        $donor = new IlluminateAuthManager(app());
        $donor->resolveUsersUsing($resolver);

        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom($donor);

        self::assertSame($resolver, $receiver->userResolver());
    }

    /**
     * The guards the replaced manager already resolved are the package
     * manager's, the same instances.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testInheritStateFromTakesOverTheResolvedGuards(): void
    {
        $guard = \Mockery::mock(Guard::class);

        $donor = new IlluminateAuthManager(app());
        $donor->extend('resolved', fn (): Guard => $guard);

        config()->set('auth.guards.resolved', ['driver' => 'resolved']);

        $donor->guard('resolved');

        $receiver = new AuthManager(app());
        $receiver->extend('resolved', fn (): Guard => \Mockery::mock(Guard::class));
        $receiver->inheritStateFrom($donor);

        self::assertTrue($receiver->hasResolvedGuards());
        self::assertSame($guard, $receiver->guard('resolved'));
    }

    /**
     * `jwt()` throws when the default guard resolves to an empty string. Pins
     * the `$guardName === ''` early-throw in `AuthManager::jwt()`.
     *
     * @return void
     */
    public function testJwtThrowsWhenDefaultGuardIsEmpty(): void
    {
        config()->set('auth.defaults.guard', '');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No default auth guard is configured.');

        $manager->jwt();
    }

    /**
     * A replaced manager with nothing registered leaves the package's manager
     * with nothing: a provider of an unregistered driver is still unknown.
     *
     * @return void
     */
    public function testInheritStateFromAnEmptyManagerTakesOverNothing(): void
    {
        $receiver = new AuthManager(app());
        $receiver->inheritStateFrom(new IlluminateAuthManager(app()));

        config()->set('auth.providers.unknown-after-empty-inherit', [
            'driver' => 'no-such-driver',
        ]);

        self::assertFalse($receiver->hasResolvedGuards());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('no-such-driver');

        $receiver->createUserProvider('unknown-after-empty-inherit');
    }

    /**
     * Register the package service provider against the Testbench application
     * so the `auth` binding is overridden by the package subclass during boot.
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
     * Configure the `test_jwt` guard over the stub identity model.
     *
     * @return void
     */
    private function configureJwtGuard(): void
    {
        config()->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);
        config()->set('auth.guards.test_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
        config()->set('authentication.jwt.keys', ['default' => 'test-secret-key-with-at-least-32-bytes!']);
        config()->set('authentication.jwt.active_kid', 'default');
        config()->set('authentication.jwt.algorithm', 'HS256');
    }

    /**
     * Read a protected property off the manager.
     *
     * @param  object  $target
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     *
     * @SuppressWarnings("php:S3011")
     */
    private static function readProperty(object $target, string $property): mixed
    {
        return (new \ReflectionProperty($target, $property))->getValue($target);
    }
}
