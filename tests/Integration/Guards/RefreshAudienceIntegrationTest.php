<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests for what a refresh and a bearer request are held to beyond
 * the token itself, against a real database on whichever engine the suite runs
 * on: the device must be one of the guard's sessions, the guard's audience
 * policy must still allow the method that started the session and still admit
 * its owner, the next idle deadline follows the policy's lifetimes for the
 * principal, and failed refreshes are counted and, past the limit, answered
 * with a 429.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class RefreshAudienceIntegrationTest extends TestCase
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $guard = app('auth')->guard('api');

            assert($guard instanceof JwtGuard);

            return ['refreshed' => $guard->refresh($request->string('refresh_token')->toString()) !== null];
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
     * A session whose device the row now records for another guard is neither
     * refreshed nor revoked, even by a replayed token, and its access token no
     * longer authenticates; once the row is the guard's again, the session
     * refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceOfAnotherGuardIsNeitherRefreshedNorRevoked(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $replay  = $this->freshGuard()->refresh($session->tokens->refreshToken);

        self::assertNotNull($replay);

        Device::query()->whereKey($session->device->getKey())->update(['guard' => 'admin']);

        $this->recordEvents([AuthenticationFailed::class, DeviceRevoked::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::DEVICE_GUARD_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->stored($session)->getRevokedAt());

        $this->bearer($replay->accessToken)->assertUnauthorized();

        Device::query()->whereKey($session->device->getKey())->update(['guard' => 'api']);

        $this->bearer($replay->accessToken)->assertOk()->assertJson(['device' => $session->device->getKey()]);

        self::assertNotNull($this->freshGuard()->refresh($replay->refreshToken));
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
        $allowed = app(AudiencePolicy::class);

        $this->bindAudience(allowsMethod: false);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->recordedEvent(AuthenticationFailed::class)->reason);

        app()->instance(AudiencePolicy::class, $allowed);

        self::assertNotNull($this->freshGuard()->refresh($session->tokens->refreshToken));
    }

    /**
     * A device that records no sign-in method fails closed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceThatRecordsNoMethodIsNotRefreshed(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        Device::query()->whereKey($session->device->getKey())->update(['sign_in_method' => null]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * An owner the guard's audience policy no longer admits cannot refresh the
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnerTheAudienceNoLongerAdmitsIsNotRefreshed(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        $this->bindAudience(admit: FailureReason::PRINCIPAL_INELIGIBLE);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A rotation moves the idle deadline by the idle lifetime the policy gives
     * the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotationFollowsThePrincipalsIdleLifetime(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        $this->bindAudience(lifetimes: new TokenLifetimes(5, 30, 60 * 24, 30));

        self::assertNotNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(
            CarbonImmutable::now()->addMinutes(30)->getTimestamp(),
            $this->stored($session)->getIdleExpiresAt()?->getTimestamp(),
        );
    }

    /**
     * A failed refresh is counted against its device and the request's IP
     * address; a successful one is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRefreshIsCountedAgainstTheDeviceAndTheIpAddress(): void
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

        self::assertNotNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertNull($this->freshGuard()->refresh('not-a-refresh-token'));
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

        $deviceId = $session->device->getDeviceIdentifier();

        $limiter->shouldReceive('blocked')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->identifier === $deviceId && $subject->ip === '198.51.100.20'))
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
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session's device as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function stored(SignedInSession $session): Device
    {
        return Device::query()->whereKey($session->device->getDeviceIdentifier())->firstOrFail();
    }

    /**
     * Bind an audience policy with the given answers, and the guard's own
     * lifetimes unless others are given.
     *
     * @param  bool  $allowsMethod
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $admit
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return void
     */
    private function bindAudience(bool $allowsMethod = true, ?FailureReason $admit = null, ?TokenLifetimes $lifetimes = null): void
    {
        $policy = \Mockery::mock(AudiencePolicy::class);

        $policy->shouldReceive('allowsMethod')->with('api', 'password')->andReturn($allowsMethod);
        $policy->shouldReceive('admit')->andReturn($admit);
        $policy->shouldReceive('lifetimes')->andReturnUsing(static fn (string $guard): TokenLifetimes => $lifetimes ?? Auth::manager()->jwt($guard)->lifetimes());

        app()->instance(AudiencePolicy::class, $policy);
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
            ->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken]);
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
