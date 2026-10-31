<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for the session service a JWT guard hands out, for a refresh
 * refused because too many have failed, and for a refresh with the token the
 * request carries.
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
     * The guard hands out the token service it was built with, the one a
     * session service built for it issues and parses with.
     *
     * @return void
     */
    public function testTokensIsTheTokenServiceTheGuardWasBuiltWith(): void
    {
        self::assertSame($this->tokens, $this->makeGuard(Request::create('/'))->tokens());
    }

    /**
     * The context's timebox runs the callback in the guard's own credential
     * timebox, with the configured budget, hands it that timebox, and returns
     * what it returns; an exception from the callback propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextsTimeboxRunsTheCallbackInTheCredentialTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 650000);

        $given = new Timebox;

        $this->timebox->shouldReceive('call')
            ->twice()
            ->with(\Mockery::type(\Closure::class), 650000)
            ->andReturnUsing(static fn (\Closure $callback): mixed => $callback($given));

        $guard    = $this->makeGuard(Request::create('/'));
        $received = null;

        self::assertSame(42, $guard->context()->timebox()->run(static function (Timebox $timebox) use (&$received): int {
            $received = $timebox;

            return 42;
        }));
        self::assertSame($given, $received);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('inside the timebox');

        $guard->context()->timebox()->run(static function (): never {
            throw new \RuntimeException('inside the timebox');
        });
    }

    /**
     * A refresh the limits refuse is counted against the request's IP address,
     * dispatches `Attempting`, `AuthenticationFailed` (`rate_limited`) and
     * `Failed` in that order, and then lets the 429 through instead of
     * returning `null`.
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

        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], array_map(static fn (object $event): string => $event::class, $dispatched));
        self::assertInstanceOf(Failed::class, $dispatched[1]);
        self::assertSame(self::GUARD_NAME, $dispatched[1]->guard);
        self::assertInstanceOf(AuthenticationFailed::class, $dispatched[2]);
        self::assertSame(AuthenticationFlow::REFRESH, $dispatched[2]->flow);
        self::assertSame(FailureReason::RATE_LIMITED, $dispatched[2]->reason);
        self::assertSame(30, $dispatched[2]->retryAfter);
        self::assertFalse($guard->hasUser());
    }

    /**
     * A bearer token that names no device binds the identity and principal as
     * an authentication, with no device and no sign-in method in its context.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testADevicelessBearerTokenReportsNoMethod(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('getTenant')->andReturnNull();

        $this->provider->shouldReceive('retrieveById')->once()->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use (&$dispatched): void {
            $dispatched[] = $event;
        });

        $guard = $this->makeGuard($this->makeRequest($this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1'])));

        self::assertSame($identity, $guard->user());
        self::assertCount(2, $dispatched);
        self::assertInstanceOf(PrincipalAssigned::class, $dispatched[1]);
        self::assertNull($dispatched[1]->context->device);
        self::assertNull($dispatched[1]->context->method);
    }

    /**
     * A request that carries no refresh token attempts nothing: no event, and
     * `null`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshFromARequestWithoutATokenAttemptsNothing(): void
    {
        $this->configureTransport();

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($this->makeGuard(Request::create('/auth/refresh', 'POST'))->refreshFromRequest());
    }

    /**
     * A token the transport refuses is reported as a failed refresh, with
     * `Attempting`, `Failed` and `AuthenticationFailed` carrying the
     * transport's reason and the request's client, and the reason is returned.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testATokenTheTransportRefusesIsAFailedRefresh(): void
    {
        $this->configureTransport();

        $dispatched = $this->recordEvents();
        $server     = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_REFRESH_TOKEN' => 'a'];
        $request    = Request::create('/auth/refresh', 'POST', ['refresh_token' => 'a'], server: $server);
        $guard      = $this->makeGuard($request);

        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $guard->refreshFromRequest());
        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], self::classesOf($dispatched));

        $failure = $dispatched[2];

        self::assertInstanceOf(AuthenticationFailed::class, $failure);
        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $failure->reason);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame('203.0.113.9', $failure->context->client->ip);
        self::assertNull($failure->context->identity);
        self::assertNull($failure->retryAfter);
        self::assertFalse($guard->hasUser());
    }

    /**
     * A token the exchange refuses fails with the exchange's reason, after the
     * same events as `refresh()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testATokenTheExchangeRefusesFailsWithItsReason(): void
    {
        $this->configureTransport();

        $dispatched = $this->recordEvents();

        $guard = $this->makeGuard(Request::create('/auth/refresh', 'POST', ['refresh_token' => 'not-a-jwt']));

        self::assertSame(FailureReason::TOKEN_INVALID, $guard->refreshFromRequest());
        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], self::classesOf($dispatched));
    }

    /**
     * A refresh with the token the request carried says where it was read from,
     * while `refresh()` with a token the caller read says nothing of it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARefreshFromTheRequestSaysWhereTheTokenWasRead(): void
    {
        $this->configureTransport();

        $this->events->shouldReceive('dispatch');

        $read   = $this->makeGuard(Request::create('/auth/refresh', 'POST', server: ['HTTP_X_REFRESH_TOKEN' => $this->liveRefreshToken('first')]))->refreshFromRequest();
        $passed = $this->makeGuard(Request::create('/auth/refresh', 'POST'))->refresh($this->liveRefreshToken('second'));

        self::assertInstanceOf(RefreshResult::class, $read);
        self::assertSame(RefreshTokenSource::HEADER, $read->source);
        self::assertNotSame('', $read->accessToken);
        self::assertSame(TokenType::REFRESH->value, $this->tokens->parse($read->refreshToken, TokenType::REFRESH)[Claims::TYPE->value] ?? null);
        self::assertInstanceOf(RefreshResult::class, $passed);
        self::assertNull($passed->source);
    }

    /**
     * A refresh with the token the request carries binds as a sign-in, with
     * `Validated` and `Login` (not remembered) before the bind events, and
     * reports `Refreshed` and then `SignedIn` (a refresh, on no new device)
     * only once the device's connection commits.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testARefreshFromTheRequestBindsASignInAndReportsItOnceCommitted(): void
    {
        $this->configureTransport();

        $dispatched = $this->recordEvents();
        $guard      = $this->makeGuard(Request::create('/auth/refresh', 'POST', ['refresh_token' => $this->liveRefreshToken('rotation')]));
        $before     = [];

        DB::transaction(static function () use ($guard, $dispatched, &$before): void {
            self::assertInstanceOf(RefreshResult::class, $guard->refreshFromRequest());

            $before = self::classesOf($dispatched);
        });

        $bind = [Attempting::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class];

        self::assertSame($bind, $before);
        self::assertSame([...$bind, Refreshed::class, SignedIn::class], self::classesOf($dispatched));
        self::assertInstanceOf(Login::class, $dispatched[2]);
        self::assertFalse($dispatched[2]->remember);
        self::assertInstanceOf(SignedIn::class, $dispatched[7]);
        self::assertTrue($dispatched[7]->refresh);
        self::assertFalse($dispatched[7]->deviceCreated);
        self::assertSame($guard->device(), $dispatched[7]->context->device);
        self::assertTrue($guard->hasUser());
    }

    /**
     * Rows of `[bind event]`: each event a refresh's bind dispatches.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideBindEvents(): iterable
    {
        yield from [
            'Validated'           => [Validated::class],
            'Login'               => [Login::class],
            'Authenticated'       => [Authenticated::class],
            'PrincipalAssigned'   => [PrincipalAssigned::class],
            'DeviceAuthenticated' => [DeviceAuthenticated::class],
        ];
    }

    /**
     * A listener that throws on any bind event fails the refresh after its
     * rotation was written, but `Refreshed` and `SignedIn` were dispatched
     * before the bind began, and the listener's exception reaches the caller.
     *
     * @param  class-string  $bindEvent
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideBindEvents')]
    public function testARefreshWhoseBindListenerThrowsIsStillReported(string $bindEvent): void
    {
        /** @var \ArrayObject<int, object> $dispatched */
        $dispatched = new \ArrayObject;

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use ($dispatched, $bindEvent): void {

            $dispatched[] = $event;

            if ($event instanceof $bindEvent) {
                throw new \RuntimeException('listener failed');
            }
        });

        $guard = $this->makeGuard(Request::create('/'));
        $token = $this->liveRefreshToken('rotation');

        try {
            $guard->refresh($token);
            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        $classes = self::classesOf($dispatched);

        self::assertSame([Attempting::class, Refreshed::class, SignedIn::class], array_slice($classes, 0, 3));
        self::assertSame([$bindEvent], array_slice($classes, -1));
    }

    /**
     * The guard's transport follows the configuration as it is when asked for.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTransportFollowsTheConfiguration(): void
    {
        $this->configureTransport();

        $guard   = $this->makeGuard(Request::create('/'));
        $request = Request::create('/auth/refresh', 'POST', server: ['HTTP_X_TOKEN' => 'a']);

        $before = $guard->refreshTransport()->read($request);

        config()->set('auth.guards.' . self::GUARD_NAME . '.refresh_token', ['header' => 'X-Token']);

        $after = $guard->refreshTransport()->read($request);

        self::assertNull($before);
        self::assertInstanceOf(PresentedRefreshToken::class, $after);
    }

    /**
     * Configure the guard and the package's refresh token defaults.
     *
     * @return void
     */
    private function configureTransport(): void
    {
        config()->set('auth.guards.' . self::GUARD_NAME, ['driver' => 'jwt', 'provider' => 'users']);
        config()->set('authentication.refresh_token', [
            'sources'    => ['body', 'header'],
            'body_field' => 'refresh_token',
            'header'     => 'X-Refresh-Token',
            'cookie'     => ['name' => '__Secure-refresh_token', 'path' => null, 'domain' => null, 'allowed_origins' => [], 'csrf_header' => 'X-Requested-With'],
        ]);
    }

    /**
     * The classes of the recorded events, in order.
     *
     * @param  \ArrayObject<int, object>  $events
     * @return list<class-string>
     */
    private static function classesOf(\ArrayObject $events): array
    {
        return array_values(array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));
    }

    /**
     * Record every event the guard dispatches.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $dispatched */
        $dispatched = new \ArrayObject;

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use ($dispatched): void {
            $dispatched[] = $event;
        });

        return $dispatched;
    }

    /**
     * A refresh token for a new live device of an identity the guard reloads,
     * acting as a principal the resolver resolves.
     *
     * @param  string  $rotationId
     * @return string
     */
    private function liveRefreshToken(string $rotationId): string
    {
        $identity = new StubIdentity;
        $identity->forceFill(['id' => 18]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '18',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
        ])->save();

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-18');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $device->forceFill(self::recordedPrincipal($principal))->save();

        $this->provider->shouldReceive('retrieveById')->once()->with('18')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-18')->andReturn($principal);

        return $this->encodeRefreshToken(['pid' => 'p-18', 'did' => $device->id, 'jti' => $rotationId]);
    }
}
