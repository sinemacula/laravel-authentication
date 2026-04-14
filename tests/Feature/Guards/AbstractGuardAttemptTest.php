<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Feature tests for the credential `attempt()` event dispatch flow on
 * `AbstractGuard`.
 *
 * Covers the Attempting/Validated/Login/Failed/Authenticated event
 * sequence for success and failure paths, including inactive
 * identity/principal rejection and unresolvable identity handling.
 * Timebox and lifecycle tests live in
 * `AbstractGuardAttemptLifecycleTest`.
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
}
