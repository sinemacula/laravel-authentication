<?php

declare(strict_types = 1);

namespace Tests\Integration\Contracts;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Pins what the flows that write a session and then bind the guard do around
 * the database's transactions and the listeners they run: a sign-in inside a
 * transaction that commits or rolls back, whose bind waits for the commit, a
 * refresh rolled back, a bind listener and a lifecycle listener that throw (and
 * what becomes of the attempt-limit slots), a request or dispatcher rebound
 * between the scheduling of the lifecycle events and their dispatch, and a
 * completion whose session write fails.
 *
 * Each assertion records what the code does today, for the refactors of the
 * session service and the guard to keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(AfterCommit::class)]
final class EventSequenceTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions, RecordsEventSequences;

    /** @var list<string> The events a sign-in's bind dispatches. */
    private const array BIND = [
        'Validated api i1',
        'Login api i1',
        'Authenticated api i1',
        'PrincipalAssigned api i1/p1/s1',
        'SessionAuthenticated api i1/p1/s1',
    ];

    /** @var list<string> The events that report a sign-in's new session. */
    private const array REPORT = [
        'SessionCreated api i1/p1/s1',
        'SignedIn api new i1/p1/s1',
    ];

    /**
     * Freeze the clocks, create the tables and seed the identity the flows sign
     * in, its own principal.
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

        $identity = $this->seedIdentity();

        $this->nameIdentities($identity);
        $this->namePrincipals($identity);
    }

    /**
     * Drop the tables and release the clocks.
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
     * Inside a transaction on the session's connection, a sign-in binds nothing
     * and gives nothing back until the transaction commits; then it reports its
     * session, binds the guard and gives its slots back, in that order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInInsideATransactionIsReportedWhenItCommits(): void
    {
        $sessions = $this->sessions();

        $this->recordSequence();

        DB::beginTransaction();

        self::assertTrue($sessions->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertSame(['Attempting api'], $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());

        DB::commit();

        self::assertSame(['Attempting api', ...self::REPORT, ...self::BIND], $this->recordedSequence());
        self::assertSame([0, 0], self::slotsTaken());
        self::assertSame(1, Session::query()->count());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * Inside a transaction that rolls back, a sign-in never binds the guard,
     * and its session is never written or reported; nothing stays counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInRolledBackIsNeverReported(): void
    {
        $guard = $this->freshGuard();

        $this->recordSequence();

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        DB::rollBack();

        self::assertSame(['Attempting api'], $this->recordedSequence());
        self::assertSame([0, 0], self::slotsTaken());
        self::assertSame(0, Session::query()->count());
        self::assertFalse($guard->hasUser());
    }

    /**
     * A refresh rolled back with the caller's transaction neither reports its
     * rotation nor binds the guard, and the presented token still refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshRolledBackIsNeverReported(): void
    {
        $session = $this->signedIn();
        $refresh = self::bodyRefreshToken($session->tokens);
        $guard   = $this->freshGuard();

        $this->nameSessions($session->record);
        $this->recordSequence();

        DB::beginTransaction();

        self::assertNotNull(self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($refresh), self::requestClient())->session);

        DB::rollBack();

        self::assertSame(['Attempting api'], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
        self::assertNotNull(self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($refresh), self::requestClient())->session);
    }

    /**
     * A bind listener that throws after the session was written reaches the
     * caller once the session is reported; the guard is left unbound and the
     * sign-in's slots stay counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindListenerThatThrowsAfterTheWrite(): void
    {
        $guard = $this->freshGuard();

        $this->recordSequence();
        $this->throwOn(Login::class);

        self::assertSame(
            'listener failed',
            self::failureOf(static fn (): SignInResult => self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())),
        );
        self::assertSame(['Attempting api', ...self::REPORT, 'Validated api i1', 'Login api i1'], $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());
        self::assertSame(1, Session::query()->count());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
        self::assertFalse($guard->hasUser());
    }

    /**
     * An activation whose bind listener throws keeps the slots its sign-in took
     * counted: they are given back only once the bind returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationWhoseBindListenerThrowsKeepsItsSlots(): void
    {
        [$credential, $proof] = $this->pendingSession();

        self::assertSame([1, 1], self::slotsTaken());

        $sessions = $this->sessions();

        $this->recordSequence();
        $this->throwOn(Authenticated::class);

        self::assertSame('listener failed', self::failureOf(static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient())));
        self::assertSame([...self::REPORT, 'Validated api i1', 'Login api i1', 'Authenticated api i1'], $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * A lifecycle listener that throws with no transaction open stops the
     * sign-in before the bind and before its slots are given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALifecycleListenerThatThrowsStopsTheSignIn(): void
    {
        $guard = $this->freshGuard();

        $this->recordSequence();
        $this->throwOn(SignedIn::class);

        self::assertSame(
            'listener failed',
            self::failureOf(static fn (): SignInResult => self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())),
        );
        self::assertSame(['Attempting api', ...self::REPORT], $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());
        self::assertSame(1, Session::query()->count());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A lifecycle listener that throws on an activation leaves the session
     * active and its slots counted: the give-back is scheduled only after the
     * report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALifecycleListenerThatThrowsOnAnActivationKeepsItsSlots(): void
    {
        [$credential, $proof] = $this->pendingSession();

        $sessions = $this->sessions();

        $this->recordSequence();
        $this->throwOn(SignedIn::class);

        self::assertSame('listener failed', self::failureOf(static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient())));
        self::assertSame(self::REPORT, $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * A request rebound between the sign-in and the commit resets the guard,
     * which the sign-in's bind, waiting for the commit, then leaves alone: the
     * guard serves another request now. The events report the client the
     * sign-in came from, and the slots are given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestReboundBeforeTheCommit(): void
    {
        $guard = $this->freshGuard();

        $this->recordSequence();
        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        app()->instance('request', Request::create('/elsewhere', 'GET', server: ['REMOTE_ADDR' => '198.51.100.9']));

        self::assertFalse($guard->hasUser());

        DB::commit();

        self::assertSame(['Attempting api', ...self::REPORT], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
        self::assertSame([0, 0], self::slotsTaken());
        self::assertSame([self::CLIENT_IP, self::CLIENT_IP], array_map(static fn (SessionCreated|SignedIn $event): ?string => $event->context->client->ip, $this->recordedAs(SessionCreated::class, SignedIn::class)));
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * A dispatcher swapped in between the scheduling of the lifecycle events
     * and the commit receives them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADispatcherSwappedBeforeTheCommitReceivesTheEvents(): void
    {
        $sessions = $this->sessions();

        $this->recordSequence();

        DB::beginTransaction();

        self::assertTrue($sessions->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        Event::fake([SessionCreated::class, SignedIn::class]);

        DB::commit();

        self::assertSame(['Attempting api', ...self::BIND], $this->recordedSequence());

        Event::assertDispatched(SessionCreated::class, 1);
        Event::assertDispatched(SignedIn::class, 1);

        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * An activation whose proof write fails rolls back: the session stays
     * pending, nothing is reported or given back, and the credential satisfies
     * it afterwards, giving its slots back once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationWhoseProofWriteFailsKeepsTheSessionPending(): void
    {
        [$credential, $proof] = $this->pendingSession();

        $sessions = $this->sessions();

        $this->recordSequence();

        Event::listen('eloquent.creating: ' . SessionProof::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient())));
        self::assertSame([], $this->recordedSequence());
        self::assertSame([1, 1], self::slotsTaken());
        self::assertSame([SessionStatus::PENDING, 1], [Session::query()->sole()->getStatus(), SessionProof::query()->count()]);

        Event::forget('eloquent.creating: ' . SessionProof::class);

        self::assertTrue($sessions->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertSame([...self::REPORT, ...self::BIND], $this->recordedSequence());
        self::assertSame([0, 0], self::slotsTaken());
        self::assertSame('s1', $this->nameOfSession(Session::query()->sole()));
    }

    /**
     * Register the guards.
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
     * The slots the sign-ins of the seeded identity hold on its identifier and
     * on the client's IP address.
     *
     * @return array{0: int, 1: int}
     */
    private static function slotsTaken(): array
    {
        return [self::counterHits('api', 'sign_in', 'per_identifier', 'ada@example.test'), self::counterHits('api', 'sign_in', 'per_ip', self::CLIENT_IP)];
    }

    /**
     * Sign the seeded identity in, as a fresh request, and return the session.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Hold a sign-in of the seeded identity for a further factor, and return
     * its pending credential and an accepted further factor's proof bound to
     * its session.
     *
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     */
    private function pendingSession(): array
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
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

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        return [$result->credential->reveal(), self::adapterProof($result->pending->identity, 'api', $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * Have a listener throw on the event, after the recording listener: for a
     * package event it listens on the contract, as the recording listener does,
     * since Laravel runs the listeners of a class before those of its
     * interfaces.
     *
     * @param  class-string  $event
     * @return void
     */
    private function throwOn(string $event): void
    {
        $listened = is_a($event, AuthenticationEvent::class, true) ? AuthenticationEvent::class : $event;

        Event::listen($listened, static function (object $dispatched) use ($event): void {
            if ($dispatched instanceof $event) {
                throw new \RuntimeException('listener failed');
            }
        });
    }

    /**
     * Run the flow, expecting a listener to throw, and return the exception's
     * message.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Sessions\SignInResult  $flow
     * @return string
     */
    private static function failureOf(\Closure $flow): string
    {
        try {
            $flow();
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }
}
