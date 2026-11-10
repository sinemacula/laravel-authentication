<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\TestCase;

/**
 * End-to-end tests for what a refresh and a bearer request are held to beyond
 * the token itself, against a real database on whichever engine the suite runs
 * on: the session must be one of the guard's sessions, the application policy
 * must still allow the method that started the session and still admit its
 * owner, the next idle deadline follows the policy's lifetimes for the guard,
 * and failed refreshes are counted and, past the limit, answered with a 429.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class RefreshApplicationIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables, and add a protected route and a
     * refresh route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $result = Auth::sessions('api')->refresh(PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()), self::requestClient());

            if ($result->reason === FailureReason::RATE_LIMITED) {
                throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
            }

            return ['refreshed' => $result->isRefreshed()];
        });
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A session the row now records for another guard is neither refreshed nor
     * revoked, even by a replayed token, and its access token no longer
     * authenticates; once the row is the guard's again, the session refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOfAnotherGuardIsNeitherRefreshedNorRevoked(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $replay  = self::sessionsOf($this->freshGuard())->refresh(
            self::bodyToken($session->tokens),
            self::requestClient(),
        )->session?->tokens;

        self::assertNotNull($replay);

        Session::query()->whereKey($session->record->getKey())->update(['guard' => 'admin']);

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->stored($session)->getRevokedAt());

        $this->bearer($replay->accessToken->reveal())->assertUnauthorized();

        Session::query()->whereKey($session->record->getKey())->update(['guard' => 'api']);

        $this->bearer($replay->accessToken->reveal())->assertOk()->assertJson(['session' => $session->record->getKey()]);

        self::assertNotNull(self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($replay), self::requestClient())->session);
    }

    /**
     * A session started by a method the guard no longer allows cannot be
     * refreshed, and is not revoked: once the method is allowed again, its
     * refresh token still works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOfAMethodNoLongerAllowedIsNotRefreshed(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $allowed = app(ApplicationPolicy::class);

        $this->bindApplicationPolicy(allowsMethod: false);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->recordedEvent(AuthenticationFailed::class)->reason);

        app()->instance(ApplicationPolicy::class, $allowed);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
    }

    /**
     * A session that records no sign-in method fails closed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatRecordsNoMethodIsNotRefreshed(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        Session::query()->whereKey($session->record->getKey())->update(['sign_in_method' => null]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A principal `ApplicationAccess` no longer lets use the application cannot
     * refresh the session, which is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalTheApplicationNoLongerAdmitsIsNotRefreshed(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A rotation moves the idle deadline by the idle lifetime the policy gives
     * the guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotationFollowsTheGuardsIdleLifetime(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        $this->bindApplicationPolicy(lifetimes: new TokenLifetimes(5, 30, 60 * 24, 30));

        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame(
            CarbonImmutable::now()->addMinutes(30)->getTimestamp(),
            $this->stored($session)->getIdleExpiresAt()?->getTimestamp(),
        );
    }

    /**
     * A failed refresh is counted against its session and the request's IP
     * address; a successful one is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRefreshIsCountedAgainstTheSessionAndTheIpAddress(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $counted = [];
        $limiter = \Mockery::mock(AttemptLimiter::class);

        $limiter->shouldReceive('blocked')->andReturnNull();
        $limiter->shouldReceive('recordFailure')
            ->once()
            ->andReturnUsing(static function (AttemptSubject $subject) use (&$counted): void {
                $counted[] = $subject;
            });

        app()->instance(AttemptLimiter::class, $limiter);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertNull(self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody('not-a-refresh-token'), self::requestClient())->session);
        self::assertCount(1, $counted);
        self::assertSame('api', $counted[0]->guard);
        self::assertSame(AttemptFlow::REFRESH, $counted[0]->flow);
        self::assertNull($counted[0]->identifier);
        self::assertNull($counted[0]->identifierType);
        self::assertSame(self::CLIENT_IP, $counted[0]->ip);
    }

    /**
     * Past the limit, the refresh route answers 429 with `Retry-After`, after
     * `AuthenticationFailed` (`rate_limited`) and `Failed`, and the session is
     * left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedRefreshIsAnswered429WithRetryAfter(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $before  = $this->stored($session)->getRefreshKey();
        $limiter = \Mockery::mock(AttemptLimiter::class);

        $sessionId = $session->record->getSessionIdentifier();

        $limiter->shouldReceive('blocked')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->identifier === $sessionId && $subject->ip === '198.51.100.20'))
            ->andReturn(17);
        $limiter->shouldNotReceive('recordFailure');

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([AuthenticationFailed::class, Failed::class]);

        $this->refresh($session)
            ->assertStatus(429)
            ->assertHeader('Retry-After', '17');

        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(17, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame($before, $this->stored($session)->getRefreshKey());
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign in with a password on the `api` guard and return the session.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(SignedInSession $session): Session
    {
        return Session::query()->whereKey($session->record->getSessionIdentifier())->firstOrFail();
    }

    /**
     * Bind an application policy with the given answer, and the guard's own
     * lifetimes unless others are given.
     *
     * @param  bool  $allowsMethod
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return void
     */
    private function bindApplicationPolicy(bool $allowsMethod = true, ?TokenLifetimes $lifetimes = null): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->shouldReceive('allowsMethod')->with('api', 'password')->andReturn($allowsMethod);
        $policy->shouldReceive('lifetimes')->andReturnUsing(static fn (string $guard): TokenLifetimes => $lifetimes ?? Auth::manager()->jwt($guard)->lifetimes());

        app()->instance(ApplicationPolicy::class, $policy);
    }

    /**
     * Send the session's refresh token to the refresh route from another
     * client.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function refresh(SignedInSession $session): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken?->reveal()]);
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }
}
