<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Feature tests for the credential `attempt()` flow on `AbstractGuard`,
 * including the timing-safe Timebox path and the standard auth event sequence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardAttemptTest extends AbstractGuardTestCase
{
    /**
     * attempt() dispatches Attempting first, then Failed on failure.
     *
     * @return void
     *
     * @throws \Throwable
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
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesValidatedAfterSuccessfulHasherCheck(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

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
            [Attempting::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class],
            $dispatched,
        );
    }

    /**
     * A successful attempt fires Login with positional (guard, identity,
     * false).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesLoginEventOnSuccess(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

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
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Authenticated::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(PrincipalAssigned::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof Login
                    && $event->guard    === self::GUARD_NAME
                    && $event->user     === $identity
                    && $event->remember === false),
            );

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A wrong-password attempt dispatches Failed and returns false.
     *
     * @return void
     *
     * @throws \Throwable
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
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user  === $identity),
            );

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A non-resolving identifier dispatches Failed and returns false.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesFailedWhenIdentifierDoesNotResolve(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user  === null),
            );

        self::assertFalse($guard->attempt(['email' => 'x']));
    }

    /**
     * `attempt()` MUST route the entire `retrieveByCredentials` →
     * `hasValidCredentials` → `fireFailedEvent` pipeline through
     * `Timebox::call()` so the elapsed time is uniform regardless of whether
     * the supplied identifier resolved to a persisted user. Before the fix, the
     * short-circuit on a null user bypassed the timebox entirely, leaking "user
     * exists" vs "user does not exist" over a timing side-channel. This test
     * asserts `Timebox::call` is invoked once even on the null-user path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptAlwaysInvokesTimeboxOnNullUserPath(): void
    {
        // Replace the default pass-through timebox expectation with a strict
        // "called exactly once" expectation that still invokes the closure so
        // the rest of the test observes the failure event dispatch.
        $this->timebox->shouldReceive('call')
            ->once()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'nonexistent@example.test']));
    }

    /**
     * A successful hasher check but null principal dispatches Failed.
     *
     * @return void
     *
     * @throws \Throwable
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
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Login::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A `CanBeActive` identity reporting `false` is rejected after the hasher
     * check passes - the resolver MUST NOT be invoked and the `Failed` event
     * fires.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesFailedWhenCanBeActiveIdentityIsInactive(): void
    {
        $guard = $this->makeGuard();

        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A resolved principal whose `isActive()` returns `false` is rejected after
     * the resolver returns; the `Login` event MUST NOT fire and `Failed` is
     * dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesFailedWhenResolvedPrincipalIsInactive(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

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

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Login::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * When the principal resolver throws `UnresolvableIdentityException` (i.e.
     * the identity model implements neither `Principal` nor `HasPrincipals`),
     * the guard catches it and converts to a `Failed` event so the request
     * returns 401, not 500.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptConvertsUnresolvableIdentityExceptionToFailedEvent(): void
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
            ->andThrow(new UnresolvableIdentityException('Cannot resolve a principal'));

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Login::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * hasValidCredentials() runs inside Timebox::call with then default
     * 400,000us budget when the package config has not set a specific
     * microsecond window.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHasValidCredentialsRunsInsideTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the 400,000
        // microsecond budget and still invokes the callback
        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

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
     * The configured `timebox.credentials_microseconds` value is passed to
     * `Timebox::call()` when the project overrides the default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetReadsConfiguredOverride(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 750000);

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 750000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

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
     * The `Attempting` event fires with `remember = false` so stateless guards
     * never advertise remember-me capability. Mutation guard: pins the literal
     * `false` in `fireAttemptingEvent()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptingEventCarriesFalseRememberParameter(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();

        $attemptingEvent = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$attemptingEvent): void {
                if ($event instanceof Attempting) {
                    $attemptingEvent = $event;
                }
            });

        $guard->attempt(['email' => 'x']);

        self::assertInstanceOf(Attempting::class, $attemptingEvent);
        self::assertFalse($attemptingEvent->remember);
    }

    /**
     * `validate()` calls `Timebox::returnEarly()` when credentials are valid,
     * so the timing budget is consumed on the success path. Mutation guard:
     * pins the `$timebox->returnEarly()` call in `validate()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateCallsReturnEarlyOnSuccessfulCredentials(): void
    {
        $returnEarlyCalled = false;

        $timeboxSpy = new class extends Timebox {
            /** @var bool Tracks whether returnEarly() was called. */
            public bool $returnEarlyCalled = false;

            /**
             * @return static
             */
            public function returnEarly(): static
            {
                $this->returnEarlyCalled = true;

                return parent::returnEarly();
            }
        };

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->andReturnUsing(static function (callable $callback) use ($timeboxSpy, &$returnEarlyCalled): mixed {
                $result            = $callback($timeboxSpy);
                $returnEarlyCalled = $timeboxSpy->returnEarlyCalled;

                return $result;
            });

        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue($guard->validate(['email' => 'x', 'password' => 'y']));
        self::assertTrue($returnEarlyCalled);
    }

    /**
     * `attempt()` calls `Timebox::returnEarly()` when credentials and principal
     * resolve successfully, so the timing budget is consumed on the success
     * path. Mutation guard: pins the `$timebox->returnEarly()` call in
     * `attempt()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptCallsReturnEarlyOnSuccess(): void
    {
        $returnEarlyCalled = false;

        $timeboxSpy = new class extends Timebox {
            /** @var bool Tracks whether returnEarly() was called. */
            public bool $returnEarlyCalled = false;

            /**
             * @return static
             */
            public function returnEarly(): static
            {
                $this->returnEarlyCalled = true;

                return parent::returnEarly();
            }
        };

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->andReturnUsing(static function (callable $callback) use ($timeboxSpy, &$returnEarlyCalled): mixed {
                $result            = $callback($timeboxSpy);
                $returnEarlyCalled = $timeboxSpy->returnEarlyCalled;

                return $result;
            });

        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        static::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
        static::assertTrue($returnEarlyCalled);
    }

    /**
     * `bindAuthenticationLifecycle()` clears prior contextual state before
     * binding the new triple, so a stale device from a previous login does not
     * leak into a deviceless `attempt()`. Mutation guard: pins the
     * `clearContextualState()` call at the top of
     * `bindAuthenticationLifecycle()`.
     *
     * @return void
     */
    public function testAttemptClearsPriorContextualStateBeforeNewBind(): void
    {
        $guard = $this->makeGuard();

        $identity1  = $this->mockIdentity();
        $principal1 = $this->mockActivePrincipal();
        $device1    = \Mockery::mock(Device::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        // First login binds identity, principal, and device.
        $guard->login($identity1, $principal1, $device1);

        static::assertSame($device1, $guard->device());

        $identity2  = $this->mockIdentity();
        $principal2 = $this->mockActivePrincipal();

        // Second login without a device must NOT carry over device1.
        $guard->login($identity2, $principal2);

        static::assertNull($guard->device());
        static::assertSame($identity2, $guard->user());
        static::assertSame($principal2, $guard->principal());
    }

    /**
     * When the `Config` facade is not bootstrapped (e.g. the guard is used
     * outside a full application boot), the `catch (\Throwable)` branch of
     * `timeboxMicroseconds()` returns the default budget rather than letting
     * the exception propagate. Mutation guard: pins the `return
     * self::DEFAULT_TIMEBOX_MICROSECONDS` inside the `catch` block.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetFallsBackToDefaultWhenConfigFacadeThrows(): void
    {
        // Set config to a non-numeric value that triggers a Throwable
        // when Config::integer() is invoked.
        config()->set('authentication.timebox.credentials_microseconds', 'not-a-number');

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        static::assertTrue($guard->validate(['email' => 'x', 'password' => 'y']));
    }

    /**
     * `attempt()` accepts an explicit `Principal` argument and uses it directly
     * instead of invoking the resolver. Pins the `$principal ??
     * $this->safeResolvePrincipal(...)` short-circuit - a mutation that swaps
     * `??` for `?:` would still pass when the caller-provided principal is
     * truthy, so we use a fresh mock the resolver MUST NOT touch.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptUsesExplicitPrincipalArgumentWithoutInvokingResolver(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $explicit = $this->mockActivePrincipal();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        // The resolver MUST NOT be called when an explicit principal is
        // supplied.
        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')->andReturnNull();

        static::assertTrue(
            $guard->attempt(
                ['email' => 'x', 'password' => 'y'],
                $explicit,
            ),
        );

        static::assertSame($explicit, $guard->principal());
    }

    /**
     * `attempt()` fires `DeviceAuthenticated` exactly once when an explicit
     * `Device` argument is supplied. Pins the `setDevice` call inside
     * `bindAuthenticationLifecycle` for the non-null device branch.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptBindsDeviceAndFiresDeviceAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $device    = \Mockery::mock(Device::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        static::assertTrue(
            $guard->attempt(
                ['email' => 'x', 'password' => 'y'],
                null,
                $device,
            ),
        );

        static::assertSame($device, $guard->device());
        static::assertContains(DeviceAuthenticated::class, $dispatched);
    }

    /**
     * `attempt()` does NOT fire `DeviceAuthenticated` when no device is
     * supplied. Pins the `if ($device !== null)` guard inside
     * `bindAuthenticationLifecycle`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDoesNotFireDeviceAuthenticatedWhenDeviceOmitted(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        static::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));

        static::assertNull($guard->device());
        static::assertNotContains(DeviceAuthenticated::class, $dispatched);
    }

    /**
     * A non-positive `timebox.credentials_microseconds` config value falls back
     * to the trait default budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetFallsBackToDefaultOnNonPositiveOverride(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 0);

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        static::assertTrue($guard->validate(['email' => 'x', 'password' => 'y']));
    }
}
