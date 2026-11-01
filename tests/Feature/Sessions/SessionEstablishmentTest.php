<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\ProvenSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
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
     * An admitted sign-in is written on a new session and reported, with
     * `SessionCreated` and then `SignedIn`, while the guard stays a guest: no
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

        $this->recordEvents([SessionCreated::class, SignedIn::class, Login::class, Authenticated::class]);

        $result = self::outcome($this->establishment($guard)->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ));

        self::assertTrue($result->isSignedIn());
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame($result->session?->record, $this->recordedEvent(SignedIn::class)->context->session);
        self::assertSame($result->session?->record, $this->recordedEvent(SessionCreated::class)->context->session);
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

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(self::outcome($this->establishment($guard)->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
    }

    /**
     * A client that proves it holds a session of the same identity and
     * principal gets a new session, and the proven one is revoked as
     * `superseded`. Once the caller's transaction commits, the revocation is
     * reported first, for the proven session with the method it records and the
     * sign-in's client, then `SessionCreated` and `SignedIn` for the new
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenSessionIsReplacedAndReportedInOrder(): void
    {
        $identity     = $this->seedIdentity();
        $guard        = $this->freshGuard();
        $establishing = $this->establishment($guard);
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'sso',
            null,
            $this->context(),
            SignInProof::unattested('sso', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $replaced = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context($first->tokens->refreshToken),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertNotNull($replaced);
        self::assertNotSame($first->record->getKey(), $replaced->record->getKey());
        self::assertSame(2, DB::table('authentication_sessions')->count());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $replaced->record->getKey())->value('revoked_at'));
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::SUPERSEDED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($first->record->getKey()), $revoked->context->sessionId);
        self::assertSame('api', $revoked->context->guard);
        self::assertSame('sso', $revoked->context->method);
        self::assertSame($identity, $revoked->context->identity);
        self::assertSame($identity, $revoked->context->principal);
        self::assertSame(self::CLIENT_IP, $revoked->context->client->ip);
        self::assertSame(IdentifierCoercion::stringify($replaced->record->getKey()), $this->recordedEvent(SessionCreated::class)->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($replaced->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);
        self::assertSame('password', $this->recordedEvent(SignedIn::class)->context->method);
        self::assertTrue($guard->guest());
    }

    /**
     * A replacement rolled back by its caller reports nothing and leaves the
     * proven session live, with no new session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackReplacementReportsNothing(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context($first->tokens->refreshToken),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->isSignedIn());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertNull(DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_at'));
    }

    /**
     * A replacement whose new session a model event cancels reports nothing,
     * and its exception reaches the caller with the proven session still live
     * at its digest and no new session written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledReplacementReportsNothing(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        $before = (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first();

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        Session::creating(static fn (): bool => false);

        try {
            self::outcome($establishing->proceed(
                self::admitted($identity),
                'password',
                'email',
                $this->context($first->tokens->refreshToken),
                SignInProof::unattested('password', CarbonImmutable::now()),
            ));
            self::fail('Expected the cancelled replacement to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(Session::class . ' was not saved: a model event cancelled the new session, so the sign-in wrote nothing.', $exception->getMessage());
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame($before, (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first());
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * A proof whose session changes before it can be replaced (here a refresh
     * rotates it while the factor policy is asked) is dropped: the sign-in is
     * reconsidered without it, the policy asked again with no proven session,
     * and a new session starts while the refreshed one stays live and
     * unreported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofThatMissesTheSwapIsReconsideredWithoutIt(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        /** @var \ArrayObject<int, mixed> $asked */
        $asked = new \ArrayObject;

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($asked, IdentifierCoercion::stringify($first->record->getKey())) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, mixed>  $asked
             * @param  ?string  $record
             */
            public function __construct(

                /** The proven session of every context asked about, in order. */
                private \ArrayObject $asked,

                /** The session a refresh rotates the first time the policy is asked. */
                private ?string $record,
            ) {}

            /**
             * Record the proven session, rotating it the first time.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                if ($this->asked->count() === 0) {
                    DB::table('authentication_sessions')->where('id', $this->record)->update(['refresh_key' => str_repeat('a', 64)]);
                }

                $this->asked->append($context->provenSession?->getSessionIdentifier());

                return false;
            }
        });

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $session = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context($first->tokens->refreshToken),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($session);
        self::assertSame([$first->record->getKey(), null], $asked->getArrayCopy());
        self::assertSame(2, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);
    }

    /**
     * A listener on the replaced session's revocation that throws stops the
     * reports after it, and its exception reaches the caller, while the
     * committed writes stand: the proven session revoked, the new one live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationListenerThatThrowsStopsTheLaterReports(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(SessionRevoked::class, static function (): void {
            throw new \RuntimeException('revocation listener failed');
        });

        try {
            self::outcome($establishing->proceed(
                self::admitted($identity),
                'password',
                'email',
                $this->context($first->tokens->refreshToken),
                SignInProof::unattested('password', CarbonImmutable::now()),
            ));
            self::fail('Expected the revocation listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('revocation listener failed', $exception->getMessage());
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame(2, DB::table('authentication_sessions')->count());
    }

    /**
     * When the additional-factor policy asks for a further factor, the sign-in
     * is held as a pending sign-in carrying the slots it took, reported by
     * `AdditionalFactorRequired` once committed; no session is written and the
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

        $this->recordEvents([AdditionalFactorRequired::class, SessionCreated::class, SignedIn::class]);

        $result = self::outcome($this->establishment($guard)->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            self::WINDOWS,
        ));

        self::assertTrue($result->requiresFactor());
        self::assertSame(0, DB::table('authentication_sessions')->count());
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
        $pending      = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            self::WINDOWS,
        ))->pending;

        self::assertNotNull($pending);

        self::requireAFurtherFactor(false);

        $found = $this->found($guard, $pending->token);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $result = $establishing->complete($found, $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
        self::assertSame([], self::released($limiter));
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(self::WINDOWS, self::released($limiter));
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertTrue($guard->guest());

        $again = $establishing->complete($found, $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(Refused::class, $again);
        self::assertSame(FailureReason::PENDING_INVALID, $again->reason);
        self::assertSame(self::WINDOWS, self::released($limiter));
    }

    /**
     * A completion of a pending sign-in that proved a session replaces that
     * session once, in the completion's transaction: one new session, the
     * proven one revoked as `superseded`, and the revocation reported before
     * the new session and the sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionReplacesTheProvenSession(): void
    {
        $identity     = $this->seedIdentity();
        $guard        = $this->freshGuard();
        $establishing = $this->establishment($guard);
        $first        = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session;

        self::assertNotNull($first);

        self::requireAFurtherFactor(true);

        $pending = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context($first->tokens->refreshToken),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->pending;

        self::assertNotNull($pending);
        self::assertNull(DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_at'));

        self::requireAFurtherFactor(false);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $result = $establishing->complete($this->found($guard, $pending->token), $this->context(), CarbonImmutable::now());

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertNotNull($result->session);
        self::assertSame(2, DB::table('authentication_sessions')->count());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($first->record->getKey()), $this->recordedEvent(SessionRevoked::class)->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($result->session->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);
    }

    /**
     * A session that continues a spent pending sign-in (a choice already used
     * up) records the client that sign-in began from as its creation, runs in
     * the client continuing it, and gives back the slots the sign-in took once
     * the caller's transaction commits.
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

        (new PendingSignIns(app(ConfigRepository::class)))->issueChoice(
            $guard->getName(),
            $identity,
            null,
            'password',
            'email',
            $began,
            SignInProof::unattested('password', CarbonImmutable::now()),
            CarbonImmutable::now(),
            self::WINDOWS,
        );

        $spent = PendingSignIn::query()->sole();

        DB::beginTransaction();

        $result = self::outcome($this->establishment($guard)->establish(
            self::admitted($identity),
            null,
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            CarbonImmutable::now(),
            self::WINDOWS,
            $spent,
        ));

        self::assertTrue($result->isSignedIn());
        self::assertSame([], self::released($limiter));

        DB::commit();

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame('198.51.100.7', $record->created_ip);
        self::assertSame(self::CLIENT_IP, $record->last_used_ip);
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
        $pending      = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            self::WINDOWS,
        ))->pending;

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
     * A sign-in whose deadline is this second or earlier is refused as
     * `session_expired` with what it admitted, before the factor policy is
     * asked or anything is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInPastItsDeadlineIsRefusedBeforeAnything(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::requireAFurtherFactor(true);

        $this->recordEvents([AdditionalFactorRequired::class, SessionCreated::class, SignedIn::class]);

        foreach ([CarbonImmutable::now(), CarbonImmutable::now()->subMinute()] as $deadline) {

            $refused = $this->establishment($guard)->proceed(
                self::admitted($identity),
                'password',
                'email',
                $this->context(notAfter: $deadline),
                SignInProof::unattested('password', CarbonImmutable::now()),
            );

            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame(FailureReason::SESSION_EXPIRED, $refused->reason);
            self::assertSame($identity, $refused->identity);
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A sign-in whose deadline is ahead starts a session capped at it: its
     * absolute deadline is the deadline, and its idle one no later.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsDeadlineCapsItsSession(): void
    {
        $identity = $this->seedIdentity();
        $deadline = CarbonImmutable::now()->addSecond();

        $establishing = $this->establishment($this->freshGuard());
        $record       = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(notAfter: $deadline),
            SignInProof::unattested('password', CarbonImmutable::now()),
        ))->session?->record;

        self::assertNotNull($record);
        self::assertSame($deadline->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($deadline->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * A pending sign-in keeps the deadline its sign-in supplied, and a
     * completion after the deadline passed while it waited is refused as
     * `session_expired`, with the pending sign-in used up and no session
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionPastTheSignInsDeadlineIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();
        $deadline = CarbonImmutable::now()->addMinute();

        self::requireAFurtherFactor(true);

        $establishing = $this->establishment($guard);
        $pending      = self::outcome($establishing->proceed(
            self::admitted($identity),
            'password',
            'email',
            $this->context(notAfter: $deadline),
            SignInProof::unattested('password', CarbonImmutable::now()),
            self::WINDOWS,
        ))->pending;

        self::assertNotNull($pending);
        self::assertSame($deadline->getTimestamp(), PendingSignIn::query()->sole()->not_after?->getTimestamp());

        $found   = $this->found($guard, $pending->token);
        $context = PendingSignIns::context($found->pending, $this->context()->client);

        self::assertSame($deadline->getTimestamp(), $context->notAfter?->getTimestamp());

        $refused = $establishing->complete($found, $context, $deadline);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::SESSION_EXPIRED, $refused->reason);
        self::assertSame($found->factor->identity, $refused->identity);
        self::assertSame($identity->getKey(), $found->factor->identity->getAuthIdentifier());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame(0, DB::table('authentication_sessions')->count());
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
            new ProvenSessions($guard->tokens()),
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
     * client presents, if any, and the deadline the session may last until, if
     * any.
     *
     * @param  ?string  $refreshToken
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(#[\SensitiveParameter] ?string $refreshToken = null, ?CarbonInterface $notAfter = null): SignInContext
    {
        return SignInContext::fromRequest(app('request'), refreshToken: $refreshToken)->withNotAfter($notAfter);
    }

    /**
     * The sign-in result establishment answered, asserting it was not refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult  $outcome
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private static function outcome(Refused|SignInResult $outcome): SignInResult
    {
        self::assertInstanceOf(SignInResult::class, $outcome);

        return $outcome;
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
