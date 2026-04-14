<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the timebox budget, lifecycle state management,
 * and explicit-argument paths on `AbstractGuard::attempt()`.
 *
 * Covers the `Timebox::call()` budget selection, the
 * `returnEarly()` call on success, `clearContextualState()` between
 * logins, and the explicit principal/device argument paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardAttemptLifecycleTest extends AbstractGuardTestCase
{
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
