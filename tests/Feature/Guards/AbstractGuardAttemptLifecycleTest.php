<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the timebox budget, contextual state and explicit arguments
 * of `AbstractGuard::attempt()`.
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
     * validate() checks the credentials inside Timebox::call with the default
     * 400,000us budget when none is configured.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateRunsInsideTimebox(): void
    {
        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = $this->mockIdentity();

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
     * A configured `timebox.credentials_microseconds` overrides the
     * `Timebox::call()` budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetReadsConfiguredOverride(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 750000);

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 750000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = $this->mockIdentity();

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
     * `validate()` calls `Timebox::returnEarly()` when the credentials are
     * valid.
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
             * Record the call before deferring to the parent.
             *
             * @return self
             */
            #[\Override]
            public function returnEarly(): self
            {
                $this->returnEarlyCalled = true;

                return parent::returnEarly();
            }
        };

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->timebox->shouldReceive('call')
            ->once()
            ->andReturnUsing(static function (callable $callback) use ($timeboxSpy, &$returnEarlyCalled): mixed {
                $result            = $callback($timeboxSpy);
                $returnEarlyCalled = $timeboxSpy->returnEarlyCalled;

                return $result;
            });

        $guard = $this->makeGuard();

        $user = $this->mockIdentity();

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
     * `attempt()` calls `Timebox::returnEarly()` when the credentials and
     * principal resolve.
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
             * Record the call before deferring to the parent.
             *
             * @return self
             */
            #[\Override]
            public function returnEarly(): self
            {
                $this->returnEarlyCalled = true;

                return parent::returnEarly();
            }
        };

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
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

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
        self::assertTrue($returnEarlyCalled);
    }

    /**
     * `attempt()` clears the prior contextual state, so a stale session does
     * not leak into a sessionless sign-in.
     *
     * @return void
     */
    public function testAttemptClearsPriorContextualStateBeforeNewBind(): void
    {
        $guard = $this->makeGuard();

        $identity1  = $this->mockIdentity();
        $principal1 = $this->mockActivePrincipal();
        $session1   = $this->mockSession();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity1, $principal1, $session1);

        self::assertSame($session1, $guard->session());

        $identity2  = $this->mockIdentity();
        $principal2 = $this->mockActivePrincipal();

        $guard->login($identity2, $principal2);

        self::assertNull($guard->session());
        self::assertSame($identity2, $guard->user());
        self::assertSame($principal2, $guard->principal());
    }

    /**
     * A budget the config cannot read as an integer falls back to the default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetFallsBackToDefaultWhenConfigFacadeThrows(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 'not-a-number');

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = $this->mockIdentity();

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
     * `attempt()` resolves an explicit principal through the resolver's hinted
     * path and binds the resolver's instance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptResolvesExplicitPrincipalThroughTheHintedPath(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $explicit = $this->mockActivePrincipal();
        $explicit->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $explicit->shouldReceive('getIdentity')->andReturn($identity);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($explicit);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue(
            $guard->attempt(
                ['email' => 'x', 'password' => 'y'],
                $explicit,
            ),
        );

        self::assertSame($explicit, $guard->principal());
    }

    /**
     * `attempt()` fires `SessionAuthenticated` once for an explicit session the
     * identity owns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptBindsSessionAndFiresSessionAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $sessionId = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

        $principal = $this->mockActivePrincipal();
        $session   = $this->pinnableSession($sessionId, $principal);

        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->once()->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);
        $sessions->shouldReceive('find')->once()->with($sessionId)->andReturn($session);

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

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

        self::assertTrue(
            $guard->attempt(
                ['email' => 'x', 'password' => 'y'],
                null,
                $session,
            ),
        );

        self::assertSame($session, $guard->session());
        self::assertContains(SessionAuthenticated::class, $dispatched);
    }

    /**
     * `attempt()` does not fire `SessionAuthenticated` when no session is
     * supplied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptDoesNotFireSessionAuthenticatedWhenSessionOmitted(): void
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

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));

        self::assertNull($guard->session());
        self::assertNotContains(SessionAuthenticated::class, $dispatched);
    }

    /**
     * A non-positive `timebox.credentials_microseconds` config value falls back
     * to the default budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTimeboxBudgetFallsBackToDefaultOnNonPositiveOverride(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 0);

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard();

        $user = $this->mockIdentity();

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
