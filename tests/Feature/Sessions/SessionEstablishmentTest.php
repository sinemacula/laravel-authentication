<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of session establishment on its own: what it writes, returns
 * and schedules for an admitted sign-in, a required further factor and a
 * completion, and that it never binds the guard, which is the session service's
 * to do once it has returned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionEstablishment::class)]
final class SessionEstablishmentTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<array<string, string>> The windows of the slots a sign-in took, as a limiter records them. */
    private const array WINDOWS = [['ip' => '1:60'], ['identifier' => '1:60']];

    /**
     * Freeze the clock and create the tables.
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
     * An admitted sign-in is written on a new device and reported, with
     * `DeviceCreated` and then `SignedIn`, while the guard stays a guest: no
     * bind event fires and nothing is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsWrittenAndReportedWithoutBindingTheGuard(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $this->recordEvents([DeviceCreated::class, SignedIn::class, Login::class, Authenticated::class]);

        $result = $this->establishment($guard)->proceed(self::admitted($identity), 'password', 'email', $this->context());

        self::assertTrue($result->isSignedIn());
        self::assertTrue($result->session?->deviceCreated);
        self::assertSame(1, DB::table('devices')->count());
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame($result->session->device, $this->recordedEvent(SignedIn::class)->context->device);
        self::assertTrue($this->recordedEvent(SignedIn::class)->deviceCreated);
        self::assertFalse($this->recordedEvent(SignedIn::class)->refresh);
        self::assertTrue($guard->guest());
    }

    /**
     * Inside a caller's transaction the reports wait for its commit, and the
     * guard is still not bound in between.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheCallersCommit(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue($this->establishment($guard)->proceed(self::admitted($identity), 'password', 'email', $this->context())->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
    }

    /**
     * A client that proves it holds a device of the same identity and principal
     * continues on it: the same device, no `DeviceCreated`, only `SignedIn`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenDeviceIsContinued(): void
    {
        $identity     = $this->seedIdentity();
        $guard        = $this->freshGuard();
        $establishing = $this->establishment($guard);
        $first        = $establishing->proceed(self::admitted($identity), 'password', 'email', $this->context())->session;

        self::assertNotNull($first);

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        $continued = $establishing->proceed(self::admitted($identity), 'password', 'email', $this->context($first->tokens->refreshToken))->session;

        self::assertNotNull($continued);
        self::assertFalse($continued->deviceCreated);
        self::assertSame($first->device->getKey(), $continued->device->getKey());
        self::assertSame(1, DB::table('devices')->count());
        self::assertSame([SignedIn::class], $this->recordedClasses());
    }

    /**
     * When the additional-factor policy asks for a further factor, the sign-in
     * is held as a pending sign-in carrying the slots it took, reported by
     * `AdditionalFactorRequired` once committed; no device is written and the
     * guard is not bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequiredFactorHoldsTheSignIn(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::requireAFurtherFactor(true);

        $this->recordEvents([AdditionalFactorRequired::class, DeviceCreated::class, SignedIn::class]);

        $result = $this->establishment($guard)->proceed(self::admitted($identity), 'password', 'email', $this->context(), self::WINDOWS);

        self::assertTrue($result->requiresFactor());
        self::assertSame(0, DB::table('devices')->count());
        self::assertSame(self::WINDOWS, PendingSignIn::query()->sole()->attempt_windows);
        self::assertSame([AdditionalFactorRequired::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
    }

    /**
     * A completion uses the pending sign-in up and writes its session in one
     * transaction, reports it, and gives back the slots the sign-in took only
     * once the caller's transaction commits; it binds nothing. The same pending
     * sign-in cannot be completed twice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionGivesItsSlotsBackOnceCommitted(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        self::requireAFurtherFactor(true);

        $establishing = $this->establishment($guard);
        $pending      = $establishing->proceed(self::admitted($identity), 'password', 'email', $this->context(), self::WINDOWS)->pending;

        self::assertNotNull($pending);

        self::requireAFurtherFactor(false);

        $found = $this->found($guard, $pending->token);

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $result = $establishing->complete($found, $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
        self::assertSame([], self::released($limiter));
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(self::WINDOWS, self::released($limiter));
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertTrue($guard->guest());

        $again = $establishing->complete($found, $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(Refused::class, $again);
        self::assertSame(FailureReason::PENDING_INVALID, $again->reason);
        self::assertSame(self::WINDOWS, self::released($limiter));
    }

    /**
     * A session that continues a spent pending sign-in (a choice already used
     * up) records the client that sign-in began from as its device's creation,
     * runs in the client continuing it, and gives back the slots the sign-in
     * took once the caller's transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASpentSignInIsContinuedFromWhereItBegan(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();
        $limiter  = new RecordingAttemptLimiter;
        $began    = SignInContext::fromRequest(Request::create('/sign-in', 'POST', server: ['REMOTE_ADDR' => '198.51.100.7']));

        app()->instance(AttemptLimiter::class, $limiter);

        (new PendingSignIns(app(ConfigRepository::class)))->issueChoice($guard->getName(), $identity, null, 'password', 'email', $began, CarbonImmutable::now(), self::WINDOWS);

        $spent = PendingSignIn::query()->sole();

        DB::beginTransaction();

        $result = $this->establishment($guard)->establish(self::admitted($identity), null, 'password', 'email', $this->context(), CarbonImmutable::now(), self::WINDOWS, $spent);

        self::assertTrue($result->isSignedIn());
        self::assertSame([], self::released($limiter));

        DB::commit();

        $device = DB::table('devices')->sole();

        self::assertSame('198.51.100.7', $device->created_ip);
        self::assertSame(self::CLIENT_IP, $device->last_used_ip);
        self::assertSame(self::WINDOWS, self::released($limiter));
        self::assertTrue($guard->guest());
    }

    /**
     * A give-back that fails is reported to the exception handler, not thrown:
     * the completed session stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGiveBackThatFailsIsReported(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::requireAFurtherFactor(true);

        $establishing = $this->establishment($guard);
        $pending      = $establishing->proceed(self::admitted($identity), 'password', 'email', $this->context(), self::WINDOWS)->pending;

        self::assertNotNull($pending);

        self::requireAFurtherFactor(false);

        $failure = new \RuntimeException('limiter down');
        $limiter = \Mockery::mock(AttemptLimiter::class);
        $handler = \Mockery::mock(ExceptionHandler::class);

        $limiter->shouldReceive('release')->once()->andThrow($failure);
        $handler->shouldReceive('report')->once()->with($failure);

        app()->instance(AttemptLimiter::class, $limiter);
        app()->instance(ExceptionHandler::class, $handler);

        $result = $establishing->complete($this->found($guard, $pending->token), $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The establishment of the guard's sessions, built from the collaborators
     * the session service builds it with.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionEstablishment
     */
    private function establishment(JwtGuard $guard): SessionEstablishment
    {
        $connections = app(ConnectionResolverInterface::class);

        return new SessionEstablishment(
            $guard->context(),
            new SessionWriter($guard->getName(), $guard->tokens(), $connections),
            new DeviceProof($guard->tokens()),
            new PendingSignIns(app(ConfigRepository::class)),
            new AfterCommit(static fn (): mixed => app('db.transactions')),
            app(),
        );
    }

    /**
     * The live pending sign-in the token names on the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn
     *
     * @throws \Throwable
     */
    private function found(JwtGuard $guard, #[\SensitiveParameter] string $token): FoundPendingSignIn
    {
        $found = (new PendingSignIns(app(ConfigRepository::class)))->find($guard->getName(), $token, $guard->getProvider(), $guard->getPrincipalResolver(), CarbonImmutable::now());

        self::assertNotNull($found);

        return $found;
    }

    /**
     * The context of a sign-in from the request, with the refresh token the
     * client presents, if any.
     *
     * @param  ?string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(#[\SensitiveParameter] ?string $refreshToken = null): SignInContext
    {
        return SignInContext::fromRequest(app('request'), refreshToken: $refreshToken);
    }

    /**
     * The windows of the reservations the limiter was given back, in order.
     *
     * @param  \Tests\Fixtures\Sessions\RecordingAttemptLimiter  $limiter
     * @return list<array<string, string>>
     */
    private static function released(RecordingAttemptLimiter $limiter): array
    {
        return array_map(static fn (AttemptReservation $reservation): array => $reservation->windows, $limiter->released);
    }

    /**
     * The identity admitted as its own principal, with no tenant.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted
     */
    private static function admitted(IntegrationIdentity $identity): Admitted
    {
        return new Admitted($identity, $identity, null);
    }

    /**
     * Bind an additional-factor policy that always gives the answer.
     *
     * @param  bool  $required
     * @return void
     */
    private static function requireAFurtherFactor(bool $required): void
    {
        app()->instance(AdditionalFactorPolicy::class, new readonly class ($required) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  bool  $required
             */
            public function __construct(

                /** The answer to give. */
                private bool $required,
            ) {}

            /**
             * Give the answer.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return $this->required;
            }
        });
    }
}
