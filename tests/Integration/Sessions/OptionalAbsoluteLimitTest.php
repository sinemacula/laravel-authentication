<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionPruning;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * End-to-end tests through the session service, against a real database on
 * whichever engine the suite runs on, for an application that sets no absolute
 * session limit, and for a sign-in that supplies a deadline of its own: a
 * session with no absolute deadline ends only when it goes idle, is listed and
 * pruned as such, and is never given one by a refresh; a sign-in's deadline
 * caps its session, alone or below the application's limit, is never moved by a
 * refresh, survives a pending sign-in, and refuses the sign-in once it has
 * passed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenLifetimes::class)]
#[CoversClass(SessionDeadlines::class)]
#[CoversClass(SessionWriter::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(ActiveSessions::class)]
#[CoversClass(SessionSummary::class)]
final class OptionalAbsoluteLimitTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard that sets no absolute limit. */
    private const string UNLIMITED = 'api';

    /** @var string Guard that keeps an absolute limit of ten hours. */
    private const string LIMITED = 'admin';

    /** @var int The idle lifetime both guards share, in minutes. */
    private const int IDLE_MINUTES = 60 * 24 * 30;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
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
     * A session of an application with no absolute limit has no absolute
     * deadline: its tokens last until it goes idle, a refresh moves only the
     * idle deadline and adds no absolute one, and it is listed with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOfAnApplicationWithNoAbsoluteLimitHasNone(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn(self::UNLIMITED);
        $idle     = $this->now->addMinutes(self::IDLE_MINUTES);

        self::assertNull($this->stored($session)->getAbsoluteExpiresAt());
        self::assertSame($idle->getTimestamp(), $this->stored($session)->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($idle->getTimestamp(), $this->expiryOf($session->tokens->refreshToken?->reveal()));

        $this->moveClocksTo($this->now->addDays(29));

        $refreshed = $this->sessions(self::UNLIMITED)->refresh($session->tokens->refreshToken?->reveal())->session;

        self::assertNotNull($refreshed);
        self::assertNull($this->stored($session)->getAbsoluteExpiresAt());
        self::assertSame($this->now->addMinutes(self::IDLE_MINUTES)->getTimestamp(), $this->stored($session)->getIdleExpiresAt()?->getTimestamp());

        $listed = $this->sessions(self::UNLIMITED)->sessions($identity)->items();

        self::assertCount(1, $listed);
        self::assertNull($listed[0]->absoluteExpiresAt);
        self::assertNull($listed[0]->toArray()['absolute_expires_at']);
        self::assertSame(1, Session::query()->active()->count());
    }

    /**
     * A session with no absolute deadline ends, and is no longer listed or
     * active, once it goes idle, and is pruned from then on with the retention.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithNoAbsoluteDeadlineEndsAndIsPrunedOnceIdle(): void
    {
        config()->set('authentication.session.prune_after_days', 0);

        $identity = $this->seedIdentity();
        $session  = $this->signedIn(self::UNLIMITED);
        $idle     = $this->now->addMinutes(self::IDLE_MINUTES);

        $this->moveClocksTo($idle->subSecond());

        self::assertSame(0, app(SessionPruning::class)->count());
        self::assertSame(1, Session::query()->active()->count());

        $this->moveClocksTo($idle);

        self::assertSame(0, Session::query()->active()->count());
        self::assertSame([], $this->sessions(self::UNLIMITED)->sessions($identity)->items());
        self::assertSame(1, app(SessionPruning::class)->prune());
        self::assertNull(Session::query()->find($session->record->getKey()));
    }

    /**
     * A sign-in's deadline caps its session: alone when the application sets no
     * absolute limit, and below the application's limit when it comes first; a
     * refresh never moves it, and the session ends at it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsDeadlineCapsItsSessionAndIsNeverMoved(): void
    {
        $this->seedIdentity();

        $deadline  = $this->now->addHours(2);
        $unlimited = $this->signedIn(self::UNLIMITED, $deadline);
        $limited   = $this->signedIn(self::LIMITED, $deadline);
        $later     = $this->signedIn(self::LIMITED, $this->now->addHours(20));

        foreach ([$unlimited, $limited] as $session) {
            self::assertSame($deadline->getTimestamp(), $this->stored($session)->getAbsoluteExpiresAt()?->getTimestamp());
            self::assertSame($deadline->getTimestamp(), $this->stored($session)->getIdleExpiresAt()?->getTimestamp());
        }

        self::assertSame($this->now->addHours(10)->getTimestamp(), $this->stored($later)->getAbsoluteExpiresAt()?->getTimestamp());

        $this->moveClocksTo($this->now->addHour());

        self::assertNotNull($this->sessions(self::UNLIMITED)->refresh($unlimited->tokens->refreshToken?->reveal())->session);
        self::assertSame($deadline->getTimestamp(), $this->stored($unlimited)->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($deadline->getTimestamp(), $this->stored($unlimited)->getIdleExpiresAt()?->getTimestamp());

        $this->moveClocksTo($deadline);

        Event::fake([AuthenticationFailed::class]);

        self::assertNull($this->sessions(self::LIMITED)->refresh($limited->tokens->refreshToken?->reveal())->session);

        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::SESSION_EXPIRED);
    }

    /**
     * A sign-in whose deadline has already passed is refused as
     * `session_expired`, and reported, with no session written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInPastItsDeadlineIsRefused(): void
    {
        $this->seedIdentity();

        Event::fake([AuthenticationFailed::class]);

        $result = $this->sessions(self::UNLIMITED)->signIn('password', self::credentials(), $this->context($this->now));

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::SESSION_EXPIRED, $result->reason);
        self::assertSame(0, Session::query()->count());

        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::SESSION_EXPIRED);
    }

    /**
     * A sign-in waiting for a further factor keeps its deadline: the pending
     * session records it as its absolute deadline and its credential expires
     * with it; satisfied before it, the session activates capped at it; once it
     * has passed, the pending session has ended with its credential, which
     * names no live pending session any more (`pending_invalid`).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionKeepsItsDeadline(): void
    {
        $identity = $this->seedIdentity();

        $this->requireAFurtherFactor();

        $deadline = $this->now->addMinute();
        $early    = $this->sessions(self::UNLIMITED)->signIn('password', self::credentials(), $this->context($deadline));
        $late     = $this->sessions(self::UNLIMITED)->signIn('password', self::credentials(), $this->context($deadline));

        self::assertNotNull($early->pending);
        self::assertNotNull($early->credential);
        self::assertNotNull($late->pending);
        self::assertNotNull($late->credential);
        self::assertSame($deadline->getTimestamp(), $early->pending->expiresAt->getTimestamp());
        self::assertSame($deadline->getTimestamp(), $early->pending->session->getAbsoluteExpiresAt()?->getTimestamp());

        $session = $this->sessions(self::UNLIMITED)->satisfy(
            $early->credential->reveal(),
            self::adapterProof($identity, self::UNLIMITED, $early->pending->id, Purpose::SIGN_IN),
        )->session;

        self::assertNotNull($session);
        self::assertSame($deadline->getTimestamp(), $this->stored($session)->getAbsoluteExpiresAt()?->getTimestamp());

        $this->moveClocksTo($deadline);

        $refused = $this->sessions(self::UNLIMITED)->satisfy($late->credential->reveal(), self::adapterProof($identity, self::UNLIMITED, $late->pending->id, Purpose::SIGN_IN));

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::PENDING_INVALID, $refused->reason);
    }

    /**
     * Configure the session guards: the 2D one with no absolute limit, the
     * other with a limit of ten hours.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.' . self::UNLIMITED . '.jwt', ['refresh_absolute_ttl_minutes' => null]);
        $config->set('auth.guards.' . self::LIMITED . '.jwt', ['refresh_absolute_ttl_minutes' => 600]);
    }

    /**
     * Sign the identity in with its password on the guard, with the deadline,
     * if any.
     *
     * @param  string  $guard
     * @param  ?\Carbon\CarbonImmutable  $deadline
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard, ?CarbonImmutable $deadline = null): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials(), $this->context($deadline))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The context of a sign-in from the request, with the deadline, if any.
     *
     * @param  ?\Carbon\CarbonImmutable  $deadline
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(?CarbonImmutable $deadline): SignInContext
    {
        return SignInContext::fromRequest(app('request'))->withNotAfter($deadline);
    }

    /**
     * The signed-in session's row as it is stored now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(SignedInSession $session): Session
    {
        $stored = Session::query()->find($session->record->getKey());

        self::assertInstanceOf(Session::class, $stored);

        return $stored;
    }

    /**
     * The expiry the 2D guard reads from its refresh token.
     *
     * @param  string  $refreshToken
     * @return mixed
     */
    private function expiryOf(string $refreshToken): mixed
    {
        return $this->freshGuard(self::UNLIMITED)->tokens()->parse($refreshToken, TokenType::REFRESH)['exp'] ?? null;
    }

    /**
     * Bind an additional-factor policy that always asks for a further factor.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Move the frozen clocks to the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
