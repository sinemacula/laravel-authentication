<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Feature tests for the session service a JWT guard hands out, and for a
 * refresh refused because too many have failed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardTest extends JwtGuardTestCase
{
    /**
     * The guard builds its session service once, from its factory, given the
     * guard itself, and hands out the same service thereafter.
     *
     * @return void
     */
    public function testBuildsItsSessionServiceOnceFromItsFactory(): void
    {
        $app = $this->app;

        assert($app !== null);

        $built    = [];
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $this->provider,
            $app->make(ConnectionResolverInterface::class),
            static fn (): null => null,
            $this->events,
            $this->resolver,
            self::GUARD_NAME,
        );

        $guard = new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            Request::create('/'),
            $this->timebox,
            $this->tokens,
            $exchange,
            function (JwtGuard $guard, \Closure $timebox) use (&$built, $app): SessionService {
                $built[] = [$guard, $timebox];

                return new SessionService($guard, $timebox, $this->tokens, $app, $app->make(ConnectionResolverInterface::class), static fn (): null => null);
            },
        );

        $sessions = $guard->sessions();

        self::assertSame($sessions, $guard->sessions());
        self::assertCount(1, $built);
        self::assertSame($guard, $built[0][0]);
    }

    /**
     * The session service is handed a runner for the guard's own credential
     * timebox, with the configured budget, which returns what the callback
     * returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHandsItsSessionServiceItsCredentialTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 750000);

        $app = $this->app;

        assert($app !== null);

        $given  = new Timebox;
        $runner = null;

        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type(\Closure::class), 750000)
            ->andReturnUsing(static fn (\Closure $callback): mixed => $callback($given));

        $guard = new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            Request::create('/'),
            $this->timebox,
            $this->tokens,
            new RefreshTokenExchange(
                $this->tokens,
                $this->provider,
                $app->make(ConnectionResolverInterface::class),
                static fn (): null => null,
                $this->events,
                $this->resolver,
                self::GUARD_NAME,
            ),
            function (JwtGuard $guard, \Closure $timebox) use (&$runner, $app): SessionService {
                $runner = $timebox;

                return new SessionService($guard, $timebox, $this->tokens, $app, $app->make(ConnectionResolverInterface::class), static fn (): null => null);
            },
        );

        $guard->sessions();

        self::assertInstanceOf(\Closure::class, $runner);

        $received = null;

        self::assertSame('outcome', $runner(static function (Timebox $timebox) use (&$received): string {
            $received = $timebox;

            return 'outcome';
        }));
        self::assertSame($given, $received);
    }

    /**
     * A refresh the limits refuse is counted against the request's IP address,
     * dispatches `Attempting`, `RefreshFailed` (`rate_limited`) and `Failed` in
     * that order, and then lets the 429 through instead of returning `null`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARateLimitedRefreshFiresFailedAndThrowsA429(): void
    {
        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->ip === '203.0.113.9' && $subject->identifier === null))
            ->andReturn(30);

        $this->app?->instance(AttemptLimiter::class, $limiter);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $guard = $this->makeGuard(Request::create('/refresh', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9']));

        try {
            $guard->refresh('not-a-jwt');
            self::fail('Expected a rate-limited refresh to throw.');
        } catch (ThrottleRequestsException $exception) {
            self::assertSame(['Retry-After' => 30], $exception->getHeaders());
        }

        self::assertSame([Attempting::class, RefreshFailed::class, Failed::class], array_map(static fn (object $event): string => $event::class, $dispatched));
        self::assertInstanceOf(RefreshFailed::class, $dispatched[1]);
        self::assertSame(RefreshFailureReason::RATE_LIMITED, $dispatched[1]->reason);
        self::assertSame(30, $dispatched[1]->retryAfter);
        self::assertInstanceOf(Failed::class, $dispatched[2]);
        self::assertSame(self::GUARD_NAME, $dispatched[2]->guard);
        self::assertFalse($guard->hasUser());
    }
}
