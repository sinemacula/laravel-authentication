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
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Feature tests for the credential `attempt()` event dispatch flow on
 * `AbstractGuard`.
 *
 * Covers the Attempting/Validated/Login/Failed/Authenticated event sequence for
 * success and failure paths, including inactive identity/principal rejection
 * and unresolvable identity handling. Timebox and lifecycle tests live in
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
     * attempt() dispatches Attempting first, then Failed and SignInFailed on
     * failure.
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
        self::assertSame([Attempting::class, Failed::class, SignInFailed::class], $dispatched);
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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason     === SignInFailureReason::INVALID_CREDENTIALS
                    && $event->identity   === null
                    && $event->identifier === 'x'
                    && $event->method     === 'password'),
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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason === SignInFailureReason::INVALID_CREDENTIALS),
            );

        self::assertFalse($guard->attempt(['email' => 'x']));
    }

    /**
     * `attempt()` MUST route the entire `retrieveByCredentials` → credential
     * check → `fireFailedEvent` pipeline through `Timebox::call()` so the
     * elapsed time is uniform regardless of whether the supplied identifier
     * resolved to a persisted user; otherwise the null-user path would leak
     * whether the identifier exists through timing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptAlwaysInvokesTimeboxOnNullUserPath(): void
    {
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
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(SignInFailed::class));

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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason    === SignInFailureReason::PRINCIPAL_UNRESOLVED
                    && $event->identity  === $identity
                    && $event->principal === null),
            );

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

        $identity = $this->mockIdentity(CanBeActive::class);
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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason   === SignInFailureReason::IDENTITY_INACTIVE
                    && $event->identity === $identity),
            );

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

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason    === SignInFailureReason::PRINCIPAL_INACTIVE
                    && $event->principal === $principal
                    && $event->tenant    === null),
            );

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * A principal acting within a `CanBeActive` tenant that reports inactive is
     * rejected; `Login` does not fire and `Failed` is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDispatchesFailedWhenPrincipalTenantIsInactive(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->once()->andReturnFalse();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->once()->andReturn($tenant);

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

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SignInFailed
                    && $event->reason    === SignInFailureReason::TENANT_INACTIVE
                    && $event->principal === $principal
                    && $event->tenant    === null),
            );

        self::assertFalse($guard->attempt(['email' => 'x', 'password' => 'y']));
        self::assertNull($guard->identity());
    }

    /**
     * Activation is opt-in: a principal that does not implement `CanBeActive`
     * is active, so the attempt binds it without consulting any active flag.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptBindsPrincipalWithoutActivationCapability(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andReturnNull();

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

        $this->events->shouldReceive('dispatch');

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
        self::assertSame($principal, $guard->principal());
    }

    /**
     * When the principal resolver throws `UnresolvableIdentityException` (i.e.
     * the identity model implements neither `Principal` nor `HasPrincipals`),
     * the misconfiguration propagates as a server error: no `Failed` event is
     * dispatched and nothing is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptPropagatesUnresolvableIdentityException(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $exception = new UnresolvableIdentityException('Cannot resolve a principal');

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow($exception);

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Validated::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Login::class));
        $this->events->shouldNotReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        try {
            $guard->attempt(['email' => 'x', 'password' => 'y']);
            self::fail('Expected the UnresolvableIdentityException to propagate.');
        } catch (UnresolvableIdentityException $caught) {
            self::assertSame($exception, $caught);
        }

        self::assertFalse($guard->hasUser());
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
                if (!$event instanceof Attempting) {
                    return;
                }

                $attemptingEvent = $event;
            });

        $guard->attempt(['email' => 'x']);

        self::assertInstanceOf(Attempting::class, $attemptingEvent);
        self::assertFalse($attemptingEvent->remember);
    }
}
