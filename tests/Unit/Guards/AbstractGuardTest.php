<?php

declare(strict_types=1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use InvalidArgumentException;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Unit tests for the AbstractGuard contextual lifecycle.
 *
 * Exercises the abstract base via a concrete test-double subclass
 * that adds no behaviour beyond forwarding the constructor parameters.
 * Collaborators (provider, resolver, dispatcher, request, timebox) are
 * mocked via Mockery; `Timebox::call` is stubbed to invoke the callback
 * directly so event-order assertions remain deterministic.
 *
 * Uses Orchestra Testbench so `config('laravel-authentication.scopes.*')`
 * is available to `isInternal()`/`isExternal()`.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class AbstractGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to the concrete test double. */
    private const string GUARD_NAME = 'test-guard';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\Illuminate\Contracts\Events\Dispatcher The mocked event dispatcher collaborator. */
    private MockInterface $events;

    /** @var \Mockery\MockInterface&\Illuminate\Http\Request The mocked HTTP request collaborator. */
    private MockInterface $request;

    /** @var \Mockery\MockInterface&\Illuminate\Support\Timebox The mocked timebox collaborator. */
    private MockInterface $timebox;

    /**
     * Define the package config keys that `isInternal()`/`isExternal()`
     * read via the `config()` helper.
     *
     * @param  \Illuminate\Foundation\Application $app The Testbench application under construction.
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('laravel-authentication.scopes.internal', 'internal');
        $config->set('laravel-authentication.scopes.external', 'external');
    }

    /**
     * Build fresh collaborator mocks before each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = Mockery::mock(IdentityProvider::class);
        $this->resolver = Mockery::mock(PrincipalResolver::class);
        $this->events   = Mockery::mock(Dispatcher::class);
        $this->request  = Mockery::mock(Request::class);
        $this->timebox  = Mockery::mock(Timebox::class);

        // Default: Timebox::call() invokes the callback directly and
        // returns its result so tests exercise the real credential
        // validation path. Tests that need to assert the 200_000
        // microsecond budget override this expectation.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox()));
    }

    /**
     * A fresh guard reports unauthenticated via check().
     *
     * @return void
     */
    public function testCheckReturnsFalseWhenNoIdentityBound(): void
    {
        $guard = $this->makeGuard();

        self::assertFalse($guard->check());
    }

    /**
     * After login(), check() reports authenticated.
     *
     * @return void
     */
    public function testCheckReturnsTrueAfterLogin(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertTrue($guard->check());
    }

    /**
     * guest() is the inverse of check() in both bound and unbound states.
     *
     * @return void
     */
    public function testGuestReturnsInverseOfCheck(): void
    {
        $guard = $this->makeGuard();

        self::assertTrue($guard->guest());

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertFalse($guard->guest());
    }

    /**
     * user() returns the identity bound by login().
     *
     * @return void
     */
    public function testUserReturnsBoundIdentity(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertSame($identity, $guard->user());
    }

    /**
     * id() returns the bound identity's auth identifier.
     *
     * @return void
     */
    public function testIdReturnsAuthIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(42);

        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertSame(42, $guard->id());
    }

    /**
     * id() is null when no identity is bound.
     *
     * @return void
     */
    public function testIdReturnsNullWhenNoIdentityBound(): void
    {
        $guard = $this->makeGuard();

        self::assertNull($guard->id());
    }

    /**
     * hasUser() reports bound state.
     *
     * @return void
     */
    public function testHasUserReturnsTrueWhenIdentityBound(): void
    {
        $guard = $this->makeGuard();

        self::assertFalse($guard->hasUser());

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertTrue($guard->hasUser());
    }

    /**
     * setUser() binds the identity and fires the Authenticated event.
     *
     * @return void
     */
    public function testSetUserBindsIdentityAndFiresAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event) use ($identity): bool {
                return $event instanceof Authenticated
                    && $event->guard === self::GUARD_NAME
                    && $event->user === $identity;
            }));

        $guard->setUser($identity);

        self::assertSame($identity, $guard->user());
    }

    /**
     * setUser() rejects Authenticatable instances that are not Identity.
     *
     * @return void
     */
    public function testSetUserThrowsInvalidArgumentExceptionForNonIdentityAuthenticatable(): void
    {
        $guard = $this->makeGuard();

        $user = Mockery::mock(Authenticatable::class);

        $this->events->shouldNotReceive('dispatch');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GUARD_NAME);

        $guard->setUser($user);
    }

    /**
     * setPrincipal() fires the PrincipalAssigned custom event.
     *
     * @return void
     */
    public function testSetPrincipalFiresPrincipalAssignedEvent(): void
    {
        $guard = $this->makeGuard();

        $principal = Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event) use ($principal): bool {
                return $event instanceof PrincipalAssigned
                    && $event->guard === self::GUARD_NAME
                    && $event->principal === $principal;
            }));

        $guard->setPrincipal($principal);

        self::assertSame($principal, $guard->principal());
    }

    /**
     * setDevice() fires the DeviceAuthenticated custom event.
     *
     * @return void
     */
    public function testSetDeviceFiresDeviceAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $device = Mockery::mock(Device::class);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event) use ($device): bool {
                return $event instanceof DeviceAuthenticated
                    && $event->guard === self::GUARD_NAME
                    && $event->device === $device;
            }));

        $guard->setDevice($device);

        self::assertSame($device, $guard->device());
    }

    /**
     * attempt() dispatches Attempting first, then Failed on failure.
     *
     * @return void
     */
    public function testAttemptDispatchesAttemptingEventBeforeValidation(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertFalse($guard->attempt(['email' => 'x']));
        self::assertSame([Attempting::class, Failed::class], $dispatched);
    }

    /**
     * A successful attempt dispatches Validated before Login and Authenticated.
     *
     * @return void
     */
    public function testAttemptDispatchesValidatedAfterSuccessfulHasherCheck(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
        self::assertSame(
            [Attempting::class, Validated::class, Authenticated::class, PrincipalAssigned::class, Login::class],
            $dispatched,
        );
    }

    /**
     * A successful attempt fires Login with positional (guard, identity, false).
     *
     * @return void
     */
    public function testAttemptDispatchesLoginEventOnSuccess(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Authenticated::class));
        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(PrincipalAssigned::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event) use ($identity): bool {
                return $event instanceof Login
                    && $event->guard === self::GUARD_NAME
                    && $event->user === $identity
                    && $event->remember === false;
            }));

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A wrong-password attempt dispatches Failed and returns false.
     *
     * @return void
     */
    public function testAttemptDispatchesFailedWhenCredentialsDoNotMatch(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnFalse();

        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Attempting::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event) use ($identity): bool {
                return $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user === $identity;
            }));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A non-resolving identifier dispatches Failed and returns false.
     *
     * @return void
     */
    public function testAttemptDispatchesFailedWhenIdentifierDoesNotResolve(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::on(static function (mixed $event): bool {
                return $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user === null;
            }));

        self::assertFalse($guard->attempt(['email' => 'x']));
    }

    /**
     * A successful hasher check but null principal dispatches Failed.
     *
     * @return void
     */
    public function testAttemptDispatchesFailedWhenPrincipalResolverReturnsNull(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturnNull();

        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Validated::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(Mockery::type(Login::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * hasValidCredentials() runs inside Timebox::call with a 200,000us budget.
     *
     * @return void
     */
    public function testHasValidCredentialsRunsInsideTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the
        // 200_000 microsecond budget and still invokes the callback.
        $this->timebox = Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(Mockery::type('callable'), 200_000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox()));

        $guard = $this->makeGuard();

        $user = Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue($guard->validate(['email' => 'x', 'password' => 'y']));
    }

    /**
     * logout() dispatches Logout and clears identity/principal/device state.
     *
     * @return void
     */
    public function testLogoutDispatchesLogoutEventAndClearsState(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = Mockery::mock(Principal::class);
        $device    = Mockery::mock(Device::class);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $guard->login($identity, $principal, $device);
        $guard->logout();

        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->device());

        $logoutEvents = array_values(array_filter(
            $dispatched,
            static fn (object $event): bool => $event instanceof Logout,
        ));

        self::assertCount(1, $logoutEvents);
        self::assertInstanceOf(Logout::class, $logoutEvents[0]);
        self::assertSame(self::GUARD_NAME, $logoutEvents[0]->guard);
        self::assertSame($identity, $logoutEvents[0]->user);
    }

    /**
     * logout() is a no-op when nothing is bound.
     *
     * @return void
     */
    public function testLogoutNoOpsWhenNoIdentityBound(): void
    {
        $guard = $this->makeGuard();

        $this->events->shouldNotReceive('dispatch');

        $guard->logout();

        self::assertNull($guard->user());
    }

    /**
     * organization() reads the principal's getOrganization().
     *
     * @return void
     */
    public function testOrganizationReturnsPrincipalsOrganization(): void
    {
        $guard = $this->makeGuard();

        $organization = Mockery::mock(Organization::class);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame($organization, $guard->organization());
    }

    /**
     * scope() reads the organization's scope string.
     *
     * @return void
     */
    public function testScopeReturnsOrganizationScope(): void
    {
        $guard = $this->makeGuard();

        $organization = Mockery::mock(Organization::class);
        $organization->shouldReceive('getOrganizationScope')
            ->andReturn('internal');

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame('internal', $guard->scope());
    }

    /**
     * isInternal() compares the scope against the configured internal key.
     *
     * @return void
     */
    public function testIsInternalReadsFromPackageConfig(): void
    {
        config()->set('laravel-authentication.scopes.internal', 'staff');

        $guard = $this->makeGuard();

        $organization = Mockery::mock(Organization::class);
        $organization->shouldReceive('getOrganizationScope')
            ->andReturn('staff');

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertTrue($guard->isInternal());
    }

    /**
     * isExternal() compares the scope against the configured external key.
     *
     * @return void
     */
    public function testIsExternalReadsFromPackageConfig(): void
    {
        config()->set('laravel-authentication.scopes.external', 'customer');

        $guard = $this->makeGuard();

        $organization = Mockery::mock(Organization::class);
        $organization->shouldReceive('getOrganizationScope')
            ->andReturn('customer');

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertTrue($guard->isExternal());
    }

    /**
     * isInternal() is false on a fresh guard with no principal.
     *
     * @return void
     */
    public function testIsInternalReturnsFalseWhenNoPrincipal(): void
    {
        $guard = $this->makeGuard();

        self::assertFalse($guard->isInternal());
    }

    /**
     * isExternal() is false on a fresh guard with no principal.
     *
     * @return void
     */
    public function testIsExternalReturnsFalseWhenNoPrincipal(): void
    {
        $guard = $this->makeGuard();

        self::assertFalse($guard->isExternal());
    }

    /**
     * Instantiate a concrete AbstractGuard subclass with the current
     * set of collaborator mocks. The subclass adds no behaviour beyond
     * forwarding its constructor arguments to the parent.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function makeGuard(): AbstractGuard
    {
        return new class (
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $this->request,
            $this->timebox,
        ) extends AbstractGuard {};
    }

    /**
     * Build a Mockery mock of the Identity contract.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function mockIdentity(): MockInterface
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = Mockery::mock(Identity::class);

        return $identity;
    }
}
