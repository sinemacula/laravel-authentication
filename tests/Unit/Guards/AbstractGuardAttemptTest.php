<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Unit tests for the credential `attempt()` flow on `AbstractGuard`,
 * including the timing-safe Timebox path and the standard auth event
 * sequence.
 *
 * Split out of the original AbstractGuardTest so each derived class
 * stays well below the project's 20-method-per-class threshold
 * (radarlint S1448).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Login
                    && $event->guard    === self::GUARD_NAME
                    && $event->user     === $identity
                    && $event->remember === false));

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
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user  === $identity));

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
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                    && $event->guard === self::GUARD_NAME
                    && $event->user  === null));

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
     * A `CanBeActive` identity reporting `false` is rejected after the
     * hasher check passes — the resolver MUST NOT be invoked and the
     * `Failed` event fires.
     *
     * @return void
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
     * A resolved principal whose `isActive()` returns `false` is
     * rejected after the resolver returns; the `Login` event MUST NOT
     * fire and `Failed` is dispatched.
     *
     * @return void
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
     * hasValidCredentials() runs inside Timebox::call with the
     * default 400,000us budget when the package config has not set
     * a specific microsecond window.
     *
     * @return void
     */
    public function testHasValidCredentialsRunsInsideTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the
        // 400_000 microsecond budget and still invokes the callback.
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
     * The configured `timebox.credentials_microseconds` value is
     * passed to `Timebox::call()` when the project overrides the
     * default.
     *
     * @return void
     */
    public function testTimeboxBudgetReadsConfiguredOverride(): void
    {
        config()->set('laravel-authentication.timebox.credentials_microseconds', 750000);

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
     * A non-positive `timebox.credentials_microseconds` config value
     * falls back to the trait default budget.
     *
     * @return void
     */
    public function testTimeboxBudgetFallsBackToDefaultOnNonPositiveOverride(): void
    {
        config()->set('laravel-authentication.timebox.credentials_microseconds', 0);

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
}
