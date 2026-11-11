<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
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
     * `sessions()` builds a session service of the named or default JWT guard
     * on each call.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testSessionsBuildsAServiceOnTheJwtGuardOnEachCall(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $guard   = $manager->guard('test_jwt');

        self::assertInstanceOf(JwtGuard::class, $guard);

        foreach ([$manager->sessions('test_jwt'), $manager->sessions()] as $sessions) {
            self::assertSame($guard->context(), self::readProperty($sessions, 'context'));
            self::assertSame($guard, self::readProperty($sessions, 'binding'));
            self::assertSame($guard->tokens(), self::readProperty($sessions, 'tokens'));
        }

        self::assertNotSame($manager->sessions(), $manager->sessions());
    }

    /**
     * A session service resolves the transactions manager from the container
     * each time it defers its events.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testSessionsAreBuiltOnTheContainerAndItsCurrentTransactionsManager(): void
    {
        $this->configureJwtGuard();

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager      = app('auth');
        $sessions     = $manager->sessions('test_jwt');
        $transactions = self::readProperty(self::readObjectProperty($sessions, 'afterCommit'), 'transactions');

        self::assertSame(app(), self::readProperty($sessions, 'container'));
        self::assertInstanceOf(\Closure::class, $transactions);
        self::assertSame(app('db.transactions'), $transactions());

        $replacement = new DatabaseTransactionsManager;

        app()->instance('db.transactions', $replacement);

        self::assertSame($replacement, $transactions());

        app()->offsetUnset('db.transactions');

        self::assertNull($transactions());
    }

    /**
     * `passkeys()` hands out a passkey service of the named or default JWT
     * guard only.
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
     * `refreshTransport()` hands out the named or default JWT guard's
     * transport.
     *
     * @return void
     */
    public function testRefreshTransportReadsWithTheJwtGuardsTransport(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');
        config()->set('auth.guards.test_jwt.refresh_token', ['header' => 'X-Token']);

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $request = Request::create('/auth/refresh', 'POST', server: ['HTTP_X_TOKEN' => 'token']);

        $named = $manager->refreshTransport('test_jwt')->extract($request);

        self::assertInstanceOf(PresentedRefreshToken::class, $named);
        self::assertSame(RefreshTokenSource::HEADER, $named->source);
        self::assertInstanceOf(PresentedRefreshToken::class, $manager->refreshTransport()->extract($request));
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
     * `forgetGuardState()` signs each resolved package guard out on the current
     * request and leaves other drivers' guards alone.
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
     * `caller()` reads the caller of the request being served.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCallerReadsTheRequestBeingServed(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn(1);
        $principal->shouldReceive('getTenant')->andReturnNull();

        app()->instance('request', Request::create('/served'));

        $manager->forgetGuards();

        $jwt = $manager->guard('test_jwt');

        self::assertInstanceOf(JwtGuard::class, $jwt);

        $jwt->login($identity, $principal);

        Event::fake([AuthenticationFailed::class]);

        $caller = $manager->caller();

        self::assertNotNull($caller);
        self::assertSame('test_jwt', $caller->guard);
        self::assertSame(CallerCredential::ACCESS, $caller->credential);
        self::assertSame($identity, $caller->identity);
        self::assertSame($principal, $caller->principal);

        $refused = Request::create('/refresh', 'POST', ['refresh_token' => 'not-a-refresh-token']);

        DeclaredCredential::refresh(null)->declareOn($refused);

        app()->instance('request', $refused);

        self::assertNull($manager->caller());

        Event::assertDispatchedTimes(AuthenticationFailed::class, 1);
    }

    /**
     * Under a default guard that is not contextual, the manager's accessors
     * answer `null`.
     *
     * @return void
     */
    public function testTheContextualAccessorsAreNullUnderAGuardThatIsNotContextual(): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $manager->extend('mocked', fn (): Guard => \Mockery::mock(Guard::class));
        config()->set('auth.guards.mocked', ['driver' => 'mocked']);
        $manager->shouldUse('mocked');

        self::assertNull($manager->identity());
        self::assertNull($manager->principal());
        self::assertNull($manager->session());
        self::assertNull($manager->tenant());
        self::assertNull($manager->context());
    }

    /**
     * `context()` answers what the bound authentication contexts answer.
     *
     * @return void
     */
    public function testContextAnswersWhatTheBoundAuthenticationContextsAnswer(): void
    {
        $nothing  = [null, null, 'api', null, [], null, false, false, false, null, null, null, null];
        $context  = new AuthenticationContext(SubjectType::PERSON, 'identity', '7', 'identity', '7', ...$nothing);
        $contexts = \Mockery::mock(AuthenticationContexts::class);
        $contexts->shouldReceive('current')->once()->andReturn($context);

        app()->instance(AuthenticationContexts::class, $contexts);

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertSame($context, $manager->context());
    }

    /**
     * `resolvedGuard()` answers a package guard only once it is resolved, and
     * never creates one.
     *
     * @return void
     */
    public function testResolvedGuardAnswersOnlyAPackageGuardAlreadyResolved(): void
    {
        $this->configureJwtGuard();

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $manager->extend('mocked', fn (): Guard => \Mockery::mock(Guard::class));
        config()->set('auth.guards.mocked', ['driver' => 'mocked']);

        self::assertNull($manager->resolvedGuard('test_jwt'));
        self::assertFalse($manager->hasResolvedGuards());
        self::assertNull($manager->resolvedGuard('unconfigured'));

        $jwt = $manager->guard('test_jwt');

        $manager->guard('mocked');

        self::assertSame($jwt, $manager->resolvedGuard('test_jwt'));
        self::assertNull($manager->resolvedGuard('mocked'));
    }

    /**
     * `inheritStateFrom()` takes over the replaced manager's guard and user
     * provider creators.
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
     * A creator bound to the replaced manager is bound to the package's manager
     * instead.
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
     * package's manager too.
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
     * A closure bound to anything but the replaced manager is taken as it is.
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
     * The replaced manager's user resolver is bound to the package's manager.
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
     * A custom user resolver set on the replaced manager is the package
     * manager's.
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
     * `jwt()` throws when the default guard resolves to an empty string.
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
     * with nothing.
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
        config()->set('authentication.jwt.issuer', 'https://issuer.example.test');
        config()->set('authentication.jwt.audience', 'https://api.example.test');
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

    /**
     * Read a property holding an object, failing the test when it holds none.
     *
     * @param  object  $target
     * @param  string  $property
     * @return object
     *
     * @throws \ReflectionException
     */
    private static function readObjectProperty(object $target, string $property): object
    {
        $value = self::readProperty($target, $property);

        self::assertIsObject($value, "The {$property} property holds no object.");

        return $value;
    }
}
