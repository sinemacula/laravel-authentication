<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\RequestGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for a JWT guard's session service, rate-limited refresh and
 * refresh from the request.
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
     * The context's timebox runs the callback in the guard's credential timebox
     * with the configured budget.
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
     * A rate-limited refresh is counted against the IP address, reported as
     * `rate_limited` and returned with the wait.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARateLimitedRefreshFiresFailedAndReturnsTheWait(): void
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

        $result = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody('not-a-jwt'), self::requestClient($guard->getRequest()));

        self::assertSame([FailureReason::RATE_LIMITED, 30], [$result->reason, $result->retryAfter]);

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
     * A bearer token that names no session binds the identity and principal as
     * an authentication, with no session and no sign-in method in its context.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASessionlessBearerTokenReportsNoMethod(): void
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

        $guard = $this->makeGuard($this->makeRequest($this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1'])));

        self::assertSame($identity, $guard->user());
        self::assertCount(2, $dispatched);
        self::assertInstanceOf(PrincipalAssigned::class, $dispatched[1]);
        EventContextAssertions::assertSession(null, $dispatched[1]->context);
        self::assertNull($dispatched[1]->context->method);
    }

    /**
     * A person's bearer token, which names no API key, is an access token in
     * the guard's authentication context, and grants no scopes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonsBearerTokenIsAnAccessTokenInItsContext(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('getTenant')->andReturnNull();

        $this->provider->shouldReceive('retrieveById')->once()->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($principal);
        $this->events->shouldReceive('dispatch');

        $context = $this->makeGuard($this->makeRequest($this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1'])))->authenticationContext();

        self::assertNotNull($context);
        self::assertSame('i-1', $context->identityId);
        self::assertSame(CredentialKind::ACCESS_TOKEN, $context->credential);
        self::assertNull($context->scopes);
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
        $this->events->shouldNotReceive('dispatch');

        $request = Request::create('/auth/refresh', 'POST');

        self::assertNull(GuardSessions::of($this->makeGuard($request))->refresh(self::servedToken(self::GUARD_NAME, $request), self::requestClient($request)));
    }

    /**
     * A token the transport refuses is reported as a failed refresh with the
     * transport's reason, which is returned.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testATokenTheTransportRefusesIsAFailedRefresh(): void
    {
        $dispatched = $this->recordEvents();
        $server     = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_REFRESH_TOKEN' => 'a'];
        $request    = Request::create('/auth/refresh', 'POST', ['refresh_token' => 'a'], server: $server);
        $guard      = $this->makeGuard($request);

        self::assertSame(
            FailureReason::REFRESH_TOKEN_CONFLICT,
            GuardSessions::of($guard)->refresh(self::servedToken(self::GUARD_NAME, $request), self::requestClient($request))?->reason,
        );
        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], self::classesOf($dispatched));

        $failure = $dispatched[2];

        self::assertInstanceOf(AuthenticationFailed::class, $failure);
        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $failure->reason);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame('203.0.113.9', $failure->context->client->ip);
        EventContextAssertions::assertIdentity(null, $failure->context);
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
        $dispatched = $this->recordEvents();

        $request = Request::create('/auth/refresh', 'POST', ['refresh_token' => 'not-a-jwt']);
        $guard   = $this->makeGuard($request);

        self::assertSame(FailureReason::TOKEN_INVALID, GuardSessions::of($guard)->refresh(self::servedToken(self::GUARD_NAME, $request), self::requestClient($request))?->reason);
        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], self::classesOf($dispatched));
    }

    /**
     * A refresh says where its token was read from, and a token the application
     * read itself came from the body.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARefreshFromTheRequestSaysWhereTheTokenWasRead(): void
    {
        $this->events->shouldReceive('dispatch');

        $header = Request::create('/auth/refresh', 'POST', server: ['HTTP_X_REFRESH_TOKEN' => $this->liveRefreshToken('first')]);
        $empty  = Request::create('/auth/refresh', 'POST');
        $read   = GuardSessions::of($this->makeGuard($header))->refresh(self::servedToken(self::GUARD_NAME, $header), self::requestClient($header));
        $passed = GuardSessions::of($this->makeGuard($empty))->refresh(PresentedRefreshToken::fromBody($this->liveRefreshToken('second')), self::requestClient($empty));

        self::assertTrue($read?->isRefreshed());
        self::assertSame(RefreshTokenSource::HEADER, $read->source);
        self::assertNotSame('', $read->session?->tokens->accessToken->reveal());
        self::assertIsArray($this->tokens->parse((string) $read->session?->tokens->refreshToken?->reveal(), TokenType::REFRESH));
        self::assertTrue($passed->isRefreshed());
        self::assertSame(RefreshTokenSource::BODY, $passed->source);
    }

    /**
     * A refresh from the request reports and binds as a sign-in only once the
     * session's connection commits.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testARefreshFromTheRequestReportsAndBindsAsASignInOnceCommitted(): void
    {
        $dispatched = $this->recordEvents();
        $request    = Request::create('/auth/refresh', 'POST', ['refresh_token' => $this->liveRefreshToken('rotation')]);
        $guard      = $this->makeGuard($request);
        $before     = [];
        $bound      = null;

        DB::transaction(static function () use ($guard, $request, $dispatched, &$before, &$bound): void {
            self::assertTrue(GuardSessions::of($guard)->refresh(self::servedToken(self::GUARD_NAME, $request), self::requestClient($request))?->isRefreshed());

            $before = self::classesOf($dispatched);
            $bound  = $guard->hasUser();
        });

        $bind = [Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class];

        self::assertSame([Attempting::class], $before);
        self::assertFalse($bound);
        self::assertSame([Attempting::class, Refreshed::class, SignedIn::class, ...$bind], self::classesOf($dispatched));
        self::assertInstanceOf(Login::class, $dispatched[4]);
        self::assertFalse($dispatched[4]->remember);
        self::assertInstanceOf(SignedIn::class, $dispatched[2]);
        self::assertTrue($dispatched[2]->refresh);
        EventContextAssertions::assertSession($guard->session(), $dispatched[2]->context);
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
            'Validated'            => [Validated::class],
            'Login'                => [Login::class],
            'Authenticated'        => [Authenticated::class],
            'PrincipalAssigned'    => [PrincipalAssigned::class],
            'SessionAuthenticated' => [SessionAuthenticated::class],
        ];
    }

    /**
     * A refresh whose bind listener throws still reports `Refreshed` and
     * `SignedIn`, and the exception reaches the caller.
     *
     * @param  class-string  $bindEvent
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     * @throws \Throwable
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
            GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()));
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
        $guard   = $this->makeGuard(Request::create('/'));
        $request = Request::create('/auth/refresh', 'POST', server: ['HTTP_X_TOKEN' => 'a']);

        $before = $guard->refreshTransport()->extract($request);

        config()->set('auth.guards.' . self::GUARD_NAME . '.refresh_token', ['header' => 'X-Token']);

        $after = $guard->refreshTransport()->extract($request);

        self::assertNull($before);
        self::assertInstanceOf(PresentedRefreshToken::class, $after);
    }

    /**
     * A JWT guard resolves as itself, the named one or the default.
     *
     * @return void
     */
    public function testAJwtGuardResolves(): void
    {
        $guard = (new \ReflectionClass(JwtGuard::class))->newInstanceWithoutConstructor();
        $auth  = \Mockery::mock(AuthManager::class);

        $auth->shouldReceive('guard')->with('api')->andReturn($guard);
        $auth->shouldReceive('guard')->with(null)->andReturn($guard);

        self::assertSame($guard, JwtGuard::from($auth, 'api', 'session service'));
        self::assertSame($guard, JwtGuard::from($auth, null, 'session service'));
    }

    /**
     * A non-JWT guard is refused, naming the guard asked for or the default.
     *
     * @return void
     */
    public function testAGuardThatIsNotAJwtGuardIsRefused(): void
    {
        $guard = (new \ReflectionClass(RequestGuard::class))->newInstanceWithoutConstructor();
        $auth  = \Mockery::mock(AuthManager::class);

        $auth->shouldReceive('guard')->andReturn($guard);
        $auth->shouldReceive('getDefaultDriver')->andReturn('web');

        try {
            JwtGuard::from($auth, 'keys', 'passkey service');
            self::fail('Expected the guard to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [keys] is not a jwt guard, so it has no passkey service.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no session service.');

        JwtGuard::from($auth, null, 'session service');
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
     * A refresh token for a new live session of an identity the guard reloads,
     * acting as a principal the resolver resolves.
     *
     * @param  string  $rotationId
     * @return string
     */
    private function liveRefreshToken(string $rotationId): string
    {
        $identity = new StubIdentity;
        $identity->forceFill(['id' => 18]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '18',
            'generation'           => (string) Str::uuid(),
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
        ])->save();

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-18');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $this->provider->shouldReceive('retrieveById')->once()->with('18')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-18')->andReturn($principal);

        return $this->encodeRefreshToken(['principal' => 'p-18', 'sid' => $session->id, 'jti' => $rotationId]);
    }
}
