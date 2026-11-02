<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget and timing contracts for the session service: what a sign-in
 * costs on a new session, on a proven session, and when it fails, and the
 * timebox that keeps a failed sign-in as slow whether or not its identifier
 * exists.
 *
 * A sign-in through a method also writes its attempt limits: it reserves a slot
 * on the identifier's and the IP address's counters (on a fresh window, for
 * each, an update that changes nothing and the insert that creates the counter;
 * later in the window, one update each), and a password checked against an
 * account reserves one on the account's counter too. A sign-in that starts its
 * session gives every slot back; one that asks for a further factor keeps them
 * all, the account's included, until its pending session first activates, which
 * then gives them back. `start()` reserves nothing, and `satisfy()` checks no
 * limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
final class SessionServiceQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /** @var int Successful sign-ins timed against the timebox. */
    private const int SUCCESSFUL_TIMING_SAMPLES = 3;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A sign-in on a new session reads the identity once, writes the session,
     * looks for proofs and provenance an earlier session left under its key
     * (one read each, which find none, so nothing is deleted), writes its first
     * proof, and reads its proofs once for the access token's `auth_time` and
     * `amr`, besides the six reservation writes and three releases of its
     * limits: binding it records no further use, since the session already
     * records the sign-in as its last.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnANewSessionReadsFourTimesAndWritesTheSessionAndItsProof(): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(4, 11, static fn (): SignInResult => $sessions->signIn('password', self::credentials()))->isSignedIn());
    }

    /**
     * Replacing a proven session reads the identity and the session, writes one
     * compare-and-swap that revokes it and one insert each of the new session
     * and its first proof, and reads what was left under the new session's key
     * (two reads, which find nothing) and its proofs once, besides reserving
     * and releasing a slot on each of the three counters the first sign-in
     * created.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnAProvenSessionReadsFiveTimesAndWritesTheReplacement(): void
    {
        $this->seedIdentity();

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $sessions = $this->sessions();
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);
        $again    = $this->assertQueryBudget(5, 9, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), $context));

        self::assertNotSame($first->record->getKey(), $again->session?->record->getKey());
    }

    /**
     * Starting a session for an externally verified identity reloads it once,
     * writes the session, reads the proofs and the provenance left under its
     * key (none), writes its first proof, and reads its proofs once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartReadsTheIdentityAndItsProofsAndWritesTheSessionAndItsProof(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(4, 2, static fn (): SignInResult => $sessions->start($identity, null, 'sso'))->isSignedIn());
    }

    /**
     * Starting a session an external provider established also writes its
     * provenance, and nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartWithAProvenanceAlsoWritesTheProvenance(): void
    {
        $identity   = $this->seedIdentity();
        $sessions   = $this->sessions();
        $provenance = new Provenance('connection-7', 'tenant-3');

        self::assertTrue($this->assertQueryBudget(4, 3, static fn (): SignInResult => $sessions->start($identity, null, 'sso', null, $provenance))->isSignedIn());
    }

    /**
     * A sign-in that needs a further factor reads the identity once, writes its
     * pending session, reads what an earlier session left under its key (two
     * reads, which find nothing) and writes its first proof, signing no token,
     * besides its limits, whose slots it keeps (the account's as well as the
     * identifier's and the IP address's); looking it up reads the session and
     * its owner; and satisfying it locks and reads the session and its owner,
     * writes the further factor's proof, checks with one `EXISTS` that the
     * session now holds an accepted one, activates the session with one update,
     * reads its proofs for the access token's `auth_time` and `amr`, and gives
     * the three slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionCostsTwoWritesAndKeepsItsSlotsUntilItActivates(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        $sessions = $this->sessions();
        $result   = $this->assertQueryBudget(3, 8, static fn (): SignInResult => $sessions->signIn('password', self::credentials()));

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential;
        $sessions   = $this->sessions();

        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?PendingSession => $sessions->pending($credential)));

        $sessions = $this->sessions();
        $proof    = self::proofFor($identity, $result->pending->id);

        self::assertTrue($this->assertQueryBudget(4, 5, static fn (): SignInResult => $sessions->satisfy($credential, $proof))->isSignedIn());
    }

    /**
     * A pending session that records a membership in a tenant costs three reads
     * more, to look up or to satisfy, than one of an identity that is its own
     * principal: the membership, its owner and its tenant, which the gate
     * admits again; the default access contracts read nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionRecordingAMembershipReadsItItsOwnerAndItsTenant(): void
    {
        [$member] = $this->seedMember();

        self::requireAFurtherFactor();

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential;
        $sessions   = $this->sessions('members');

        self::assertNotNull($this->assertQueryBudget(5, 0, static fn (): ?PendingSession => $sessions->pending($credential)));

        $sessions = $this->sessions('members');
        $proof    = self::proofFor($member, $result->pending->id, 'members');

        self::assertTrue($this->assertQueryBudget(7, 5, static fn (): SignInResult => $sessions->satisfy($credential, $proof))->isSignedIn());
    }

    /**
     * Satisfying a pending session that proved a session reads that session
     * again on the write connection, once, and revokes it with one
     * compare-and-swap, besides what any activation costs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSatisfyingAPendingSessionThatProvedASessionSupersedesIt(): void
    {
        $identity = $this->seedIdentity();

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        self::requireAFurtherFactor();

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);
        $pending = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential;
        $proof      = self::proofFor($identity, $pending->pending->id);
        $sessions   = $this->sessions();
        $result     = $this->assertQueryBudget(5, 6, static fn (): SignInResult => $sessions->satisfy($credential, $proof));

        self::assertSame($pending->pending->id, $result->session?->record->getKey());
        self::assertSame('superseded', Session::query()->whereKey($first->record->getKey())->value('revoked_reason'));
    }

    /**
     * Discarding a pending session locks and reads it and its owner, and
     * revokes it; a credential that names none costs the one read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDiscardingAPendingSessionReadsItAndItsOwnerAndRevokesIt(): void
    {
        $this->seedIdentity();

        self::requireAFurtherFactor();

        $credential = $this->sessions()->signIn('password', self::credentials())->credential;

        self::assertNotNull($credential);

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(2, 1, static fn (): bool => $sessions->discard($credential)));
        self::assertFalse($this->assertQueryBudget(1, 0, static fn (): bool => $sessions->discard($credential)));
    }

    /**
     * Satisfying with a credential that names no pending session costs no more
     * than the one read that finds none, writes nothing, and checks no limit: a
     * credential whose session already activated, and a garbled one, which
     * costs no query at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSatisfyingWithACredentialThatNamesNothingCostsAtMostOneRead(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential;
        $proof      = self::proofFor($identity, $result->pending->id);

        self::assertTrue($this->sessions()->satisfy($credential, $proof)->isSignedIn());

        $sessions = $this->sessions();

        self::assertSame(FailureReason::PENDING_INVALID, $this->assertQueryBudget(1, 0, static fn (): SignInResult => $sessions->satisfy($credential, $proof))->reason);
        self::assertSame(
            FailureReason::PENDING_INVALID,
            $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->satisfy('not-a-pending-credential', $proof))->reason,
        );
    }

    /**
     * Rows of `[credentials, writes]`: sign-ins that fail, with and without a
     * known identifier, and the reservation writes each keeps (a wrong password
     * also reserves the account's slot).
     *
     * @return iterable<string, array{0: array<string, string>, 1: int}>
     */
    public static function provideFailedCredentials(): iterable
    {
        yield from [
            'unknown identifier' => [['email' => 'nobody@example.test', 'password' => self::PASSWORD], 4],
            'wrong password'     => [['email' => 'ada@example.test', 'password' => 'wrong'], 6],
        ];
    }

    /**
     * A failed sign-in reads the identity once, writes only the reservations it
     * keeps, and waits out the real timebox whether or not the identifier
     * exists.
     *
     * @param  array<string, string>  $credentials
     * @param  int  $writes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailedCredentials')]
    public function testAFailedSignInReadsOnceWritesOnlyItsLimitsAndWaitsOutTheTimebox(array $credentials, int $writes): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(1, $writes, static fn (): SignInResult => $sessions->signIn('password', $credentials))->isFailed());

        $this->useTimebox();

        $sessions = $this->sessions();
        $started  = hrtime(true);

        self::assertTrue($sessions->signIn('password', $credentials)->isFailed());
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
    }

    /**
     * A successful sign-in returns as soon as it is done instead of waiting out
     * the timebox. The fastest of a few sign-ins is compared, so one scheduler
     * pause cannot fail the contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInReturnsBeforeTheTimebox(): void
    {
        $this->seedIdentity();
        $this->useTimebox();

        $fastest = PHP_INT_MAX;

        for ($attempt = 0; $attempt < self::SUCCESSFUL_TIMING_SAMPLES; $attempt++) {

            $sessions = $this->sessions();
            $started  = hrtime(true);

            self::assertTrue($sessions->signIn('password', self::credentials())->isSignedIn());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
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
     * An accepted further factor's proof, made now by the identity for the
     * pending session of the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $sessionId
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private static function proofFor(Identity $identity, mixed $sessionId, string $guard = 'api'): ProofResult
    {
        return new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-1',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($identity, $guard, $sessionId, Purpose::SIGN_IN),
        );
    }

    /**
     * Bind an additional-factor policy that asks every sign-in for a further
     * factor.
     *
     * @return void
     */
    private static function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
    }

    /**
     * Use the real timebox length for the timing contracts.
     *
     * @return void
     */
    private function useTimebox(): void
    {
        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);
    }
}
