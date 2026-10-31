<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of refreshing a session through the session service: the
 * rotated session it returns and the guard bound to it, the events in their
 * order, each refusal returned with its reason, `rate_limited` with its wait
 * rather than a thrown 429, and where a refresh read from the request found its
 * token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRefresh::class)]
#[CoversClass(RefreshResult::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(RefreshesSessions::class)]
final class SessionRefreshTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a refresh dispatches. */
    private const array EVENTS = [
        Attempting::class,
        Refreshed::class,
        SignedIn::class,
        Validated::class,
        Login::class,
        Authenticated::class,
        PrincipalAssigned::class,
        DeviceAuthenticated::class,
        Failed::class,
        AuthenticationFailed::class,
    ];

    /** @var list<class-string> The events of a refresh outside a transaction, in order. */
    private const array REFRESHED = [
        Attempting::class,
        Refreshed::class,
        SignedIn::class,
        Validated::class,
        Login::class,
        Authenticated::class,
        PrincipalAssigned::class,
        DeviceAuthenticated::class,
    ];

    /** @var list<class-string> The events of a refused refresh, in order. */
    private const array REFUSAL = [Attempting::class, Failed::class, AuthenticationFailed::class];

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
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
     * A refresh rotates the session's refresh token on its device, reports the
     * rotation with `Refreshed` and then `SignedIn` (a refresh, on no new
     * device), and then binds the guard as a sign-in; the result carries the
     * session on the same device with the new pair, and no source, reason or
     * wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshRotatesTheSessionAndBindsTheGuardToIt(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $before   = $this->refreshKeyOf($session);
        $guard    = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh($session->tokens->refreshToken);

        self::assertTrue($result->isRefreshed());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertNull($result->source);

        $refreshed = $result->session;

        self::assertInstanceOf(SignedInSession::class, $refreshed);
        self::assertTrue($identity->is($refreshed->identity));
        self::assertSame($session->device->getKey(), $refreshed->device->getKey());
        self::assertSame('password', $refreshed->method);
        self::assertFalse($refreshed->deviceCreated);
        self::assertNotSame($before, $this->refreshKeyOf($session));

        $rotation = $this->claimsOf($refreshed->tokens->refreshToken)[Claims::JWT_ID->value] ?? null;

        self::assertIsString($rotation);
        self::assertSame($this->refreshKeyOf($session), RefreshTokenHasher::hash($rotation));
        self::assertSame($session->device->getKey(), $this->claimsOf($refreshed->tokens->accessToken, TokenType::ACCESS)[Claims::DEVICE_ID->value] ?? null);

        self::assertSame(self::REFRESHED, $this->recordedClasses());

        $attempting = $this->recordedEvent(Attempting::class);
        $signedIn   = $this->recordedEvent(SignedIn::class);

        self::assertSame(['api', [], false], [$attempting->guard, $attempting->credentials, $attempting->remember]);
        self::assertSame($refreshed->device, $this->recordedEvent(Refreshed::class)->context->device);
        self::assertSame(self::CLIENT_IP, $this->recordedEvent(Refreshed::class)->context->client->ip);
        self::assertSame([true, false], [$signedIn->refresh, $signedIn->deviceCreated]);
        self::assertSame('password', $signedIn->context->method);
        self::assertSame($refreshed->identity, $this->recordedEvent(Validated::class)->user);
        self::assertSame($refreshed->identity, $this->recordedEvent(Login::class)->user);
        self::assertFalse($this->recordedEvent(Login::class)->remember);

        self::assertSame($refreshed->identity, $guard->user());
        self::assertSame($refreshed->principal, $guard->principal());
        self::assertSame($refreshed->device, $guard->device());
    }

    /**
     * The bind events carry the tenant the refresh admitted the principal in
     * and the sign-in method the device records, as the rotation's report does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBindReportsTheTenantAndMethodTheRefreshEstablished(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');
        $guard   = $this->freshGuard('members');

        $this->recordEvents([Refreshed::class, PrincipalAssigned::class, DeviceAuthenticated::class]);

        self::assertTrue(self::sessionsOf($guard)->refresh($session->tokens->refreshToken)->isRefreshed());

        foreach ($this->recorded as $event) {

            self::assertInstanceOf(AuthenticationEvent::class, $event);

            $context = $event->context();

            self::assertTrue($tenant->is($context->tenant));
            self::assertTrue($membership->is($context->principal));
            self::assertSame('password', $context->method);
        }

        self::assertCount(3, $this->recorded);
        self::assertTrue($tenant->is($guard->tenant()));
    }

    /**
     * Every refusal of the exchange is returned with its reason, after
     * `Attempting`, Laravel's `Failed` (no user, no credentials) and
     * `AuthenticationFailed` with the same reason, and binds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusalIsReturnedWithItsReason(): void
    {
        $this->seedIdentity();

        $replayed = $this->signedIn();
        $unknown  = $this->signedIn();
        $revoked  = $this->signedIn();

        self::assertTrue(self::sessionsOf($this->freshGuard())->refresh($replayed->tokens->refreshToken)->isRefreshed());

        Device::query()->whereKey($unknown->device->getKey())->delete();
        Device::query()->whereKey($revoked->device->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'signed_out']);

        $this->moveTo(CarbonImmutable::now()->addMinute());

        $cases = [
            'not-a-token'                   => FailureReason::TOKEN_INVALID,
            $unknown->tokens->refreshToken  => FailureReason::DEVICE_UNKNOWN,
            $revoked->tokens->refreshToken  => FailureReason::DEVICE_REVOKED,
            $replayed->tokens->refreshToken => FailureReason::ROTATION_REUSE,
        ];

        foreach ($cases as $token => $reason) {

            $guard = $this->freshGuard();

            $this->recordEvents(self::EVENTS);

            $result = self::sessionsOf($guard)->refresh($token);

            self::assertTrue($result->isFailed(), $reason->value);
            self::assertFalse($result->isRefreshed());
            self::assertNull($result->session);
            self::assertSame($reason, $result->reason);
            self::assertNull($result->retryAfter);
            self::assertNull($result->source);
            self::assertSame(self::REFUSAL, $this->recordedClasses(), $reason->value);

            $failed  = $this->recordedEvent(Failed::class);
            $failure = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame(['api', null, []], [$failed->guard, $failed->user, $failed->credentials]);
            self::assertSame([AuthenticationFlow::REFRESH, $reason], [$failure->flow, $failure->reason]);
            self::assertTrue($guard->guest());
        }
    }

    /**
     * A refresh the limits refuse is returned as `rate_limited` with the wait
     * the failure reports, after the same events as any refusal; nothing is
     * thrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedRefreshIsReturnedWithItsWait(): void
    {
        config()->set('authentication.rate_limits.refresh.per_ip.max', 1);

        self::assertSame(FailureReason::TOKEN_INVALID, self::sessionsOf($this->freshGuard())->refresh('not-a-token')->reason);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($this->freshGuard())->refresh('not-a-token');

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertSame(60, $result->retryAfter);
        self::assertSame(self::REFUSAL, $this->recordedClasses());
        self::assertSame(60, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
    }

    /**
     * A refresh read from the request says where its token came from, the body
     * or a header, whether it was refreshed or refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshFromTheRequestSaysWhereItsTokenWasRead(): void
    {
        $this->seedIdentity();

        $fromHeader = $this->signedIn()->tokens->refreshToken;
        $fromBody   = $this->signedIn()->tokens->refreshToken;

        $header = self::sessionsOf($this->guardServing(['HTTP_X_REFRESH_TOKEN' => $fromHeader]))->refreshFromRequest();
        $body   = self::sessionsOf($this->guardServing([], ['refresh_token' => $fromBody]))->refreshFromRequest();
        $refuse = self::sessionsOf($this->guardServing([], ['refresh_token' => 'not-a-token']))->refreshFromRequest();

        self::assertSame([true, RefreshTokenSource::HEADER], [$header?->isRefreshed(), $header?->source]);
        self::assertSame([true, RefreshTokenSource::BODY], [$body?->isRefreshed(), $body?->source]);
        self::assertSame([FailureReason::TOKEN_INVALID, RefreshTokenSource::BODY], [$refuse?->reason, $refuse?->source]);
    }

    /**
     * A request that carries no refresh token is not a refresh: `null`, and
     * nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutATokenIsNotARefresh(): void
    {
        $this->recordEvents(self::EVENTS);

        self::assertNull(self::sessionsOf($this->freshGuard())->refreshFromRequest());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A token the transport refuses is a refused refresh, reported with the
     * transport's reason and the request's client and no identity, returned
     * with no source, and the device is left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenTheTransportRefusesIsARefusedRefresh(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = $session->tokens->refreshToken;
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->guardServing(['HTTP_X_REFRESH_TOKEN' => $token], ['refresh_token' => $token]);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refreshFromRequest();

        self::assertNotNull($result);
        self::assertSame([FailureReason::REFRESH_TOKEN_CONFLICT, null, null], [$result->reason, $result->retryAfter, $result->source]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());
        $attempting = $this->recordedEvent(Attempting::class);

        self::assertSame(['api', [], false], [$attempting->guard, $attempting->credentials, $attempting->remember]);
        self::assertNull($this->recordedEvent(Failed::class)->user);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::REFRESH, FailureReason::REFRESH_TOKEN_CONFLICT], [$failure->flow, $failure->reason]);
        self::assertSame(['api', self::CLIENT_IP, null], [$failure->context->guard, $failure->context->client->ip, $failure->context->identity]);
        self::assertSame($before, $this->refreshKeyOf($session));
        self::assertTrue($guard->guest());
    }

    /**
     * The rotation is reported before the guard is bound: a `Login` listener
     * that throws propagates, after `Refreshed` and `SignedIn` were dispatched
     * for the rotation already written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRotationIsReportedBeforeTheBind(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        try {
            self::sessionsOf($guard)->refresh($session->tokens->refreshToken);
            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([Attempting::class, Refreshed::class, SignedIn::class, Validated::class, Login::class], $this->recordedClasses());
        self::assertNotSame($before, $this->refreshKeyOf($session));
    }

    /**
     * Inside the caller's transaction the rotation's report waits for the
     * commit, so it follows the bind events, and a rollback drops it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportWaitsForTheCallersCommit(): void
    {
        $this->seedIdentity();

        $committed  = $this->signedIn();
        $rolledBack = $this->signedIn();

        $this->recordEvents(self::EVENTS);

        DB::transaction(fn (): bool => self::sessionsOf($this->freshGuard())->refresh($committed->tokens->refreshToken)->isRefreshed());

        self::assertSame([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            DeviceAuthenticated::class,
            Refreshed::class,
            SignedIn::class,
        ], $this->recordedClasses());

        $this->recordEvents(self::EVENTS);

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($this->freshGuard())->refresh($rolledBack->tokens->refreshToken)->isRefreshed());

        DB::rollBack();

        self::assertNotContains(Refreshed::class, $this->recordedClasses());
        self::assertNotContains(SignedIn::class, $this->recordedClasses());
    }

    /**
     * A session service handed out before a dispatcher is swapped in reports
     * its refresh to the dispatcher bound then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAServiceHandedOutBeforeAFakeReportsToIt(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn();
        $sessions = self::sessionsOf($this->freshGuard());

        Event::fake(self::EVENTS);

        self::assertTrue($sessions->refresh($session->tokens->refreshToken)->isRefreshed());

        foreach (self::REFRESHED as $class) {
            Event::assertDispatched($class);
        }

        Event::assertNotDispatched(Failed::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
    }

    /**
     * Configure the guards and providers.
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
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Start a request from the test client with the server values and body, and
     * resolve the `api` guard afresh for it.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardServing(array $server, array $body = []): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST', $body, server: ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => self::CLIENT_AGENT, ...$server]));

        Auth::forgetGuards();

        $resolved = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $resolved);

        return $resolved;
    }

    /**
     * The refresh key the session's device stores now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private function refreshKeyOf(SignedInSession $session): mixed
    {
        return Device::query()->whereKey($session->device->getKey())->value('refresh_key');
    }

    /**
     * The claims of a token of the `api` guard.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function claimsOf(#[\SensitiveParameter] string $token, TokenType $type = TokenType::REFRESH): array
    {
        $claims = Auth::jwt('api')->parse($token, $type);

        self::assertNotNull($claims);

        return $claims;
    }

    /**
     * Move the clock, and the token library's, to the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function moveTo(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
