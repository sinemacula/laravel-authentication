<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
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
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;

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
    use InteractsWithExternalSignIns, InteractsWithSessions;

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
     * proof, reads its proofs once for the access token's `auth_time` and
     * `amr`, and, once the session is committed, reads the identity again to
     * check it still stands (it is its own principal, so it is read once),
     * besides the six reservation writes and three releases of its limits:
     * binding it records no further use, since the session already records the
     * sign-in as its last.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnANewSessionReadsFiveTimesAndWritesTheSessionAndItsProof(): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(5, 11, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()))->isSignedIn());
    }

    /**
     * Inside a caller's transaction a sign-in costs what one alone does, and
     * one read more at the commit: its bind, which waited for the commit, reads
     * the session again before binding it. With no transaction open the bind
     * runs at once and reads nothing. The check of the identity waits for the
     * commit too, and costs the same one read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindThatWaitsForTheCommitReadsTheSessionOnce(): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        $signIn = static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext());

        self::assertTrue($this->assertQueryBudget(6, 11, static fn (): SignInResult => DB::transaction($signIn))->isSignedIn());
    }

    /**
     * A cookie application's sign-in costs what a body application's does:
     * delivering the refresh token in the cookie, with its expiry read from the
     * session it has just written, adds no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsSignInCostsWhatASignInCosts(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $this->seedIdentity();

        $sessions = $this->sessions('admin');
        $result   = $this->assertQueryBudget(5, 11, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()));

        self::assertNull($result->session?->tokens->refreshToken);
        self::assertSame('__Secure-admin_refresh_token', $result->session?->tokens->refreshCookie?->name);
    }

    /**
     * A cookie application's sign-in from another site is refused before
     * anything is read or counted, so it costs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACrossSiteSignInOnACookieApplicationCostsNoQuery(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $this->seedIdentity();

        $sessions = $this->sessions('admin');

        request()->headers->set('Origin', 'https://evil.example.test');
        request()->headers->remove('X-Requested-With');

        $result = $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()));

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $result->reason);
    }

    /**
     * A cookie application's `start()` from another site is refused before the
     * identity is reloaded, so it costs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACrossSiteStartOnACookieApplicationCostsNoQuery(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $identity = $this->seedIdentity();
        $sessions = $this->sessions('admin');

        request()->headers->set('Origin', 'https://evil.example.test');
        request()->headers->remove('X-Requested-With');

        $result = $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->start($identity, null, 'sso', self::requestContext()));

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $result->reason);
    }

    /**
     * A cookie application's `satisfy()` and `choose()` from another site, for
     * a live pending session, are refused before the pending session is read,
     * so each costs no query, as are those given a client the same-site check
     * refuses.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACrossSitePendingActionOnACookieApplicationCostsNoQuery(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        $result = $this->sessions('admin')->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $proof      = self::proofFor($identity, $result->pending->id, 'admin');
        $sessions   = $this->sessions('admin');

        request()->headers->set('Origin', 'https://evil.example.test');
        request()->headers->remove('X-Requested-With');

        self::assertSame(
            FailureReason::CROSS_SITE_REQUEST,
            $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()))->reason,
        );
        self::assertSame(
            FailureReason::CROSS_SITE_REQUEST,
            $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->choose($credential, $identity, self::requestClient()))->reason,
        );
        self::assertNotNull($this->sessions('admin')->pending($credential));

        $sessions = $this->sessions('admin');
        $client   = self::crossSiteClient();
        $satisfy  = static fn (): SignInResult => $sessions->satisfy($credential, $proof, $client);
        $choose   = static fn (): SignInResult => $sessions->choose($credential, $identity, $client);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->assertQueryBudget(0, 0, $satisfy)->reason);
        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->assertQueryBudget(0, 0, $choose)->reason);
        self::assertNotNull($this->sessions('admin')->pending($credential));
    }

    /**
     * A cookie application's satisfaction given a same-site client, though the
     * guard's own request comes from another site, costs what a satisfaction
     * given the client of a same-site request costs: judging the client given
     * reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionGivenASameSiteClientCostsWhatOneFromASameSiteRequestCosts(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        $result = $this->sessions('admin')->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $proof      = self::proofFor($identity, $result->pending->id, 'admin');

        request()->headers->set('Origin', 'https://evil.example.test');
        request()->headers->remove('X-Requested-With');

        $sessions = $this->sessions('admin');
        $result   = $this->assertQueryBudget(5, 6, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::sameSiteClient()));

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session?->tokens->refreshCookie);
    }

    /**
     * Replacing a proven session reads the identity and the session, writes one
     * compare-and-swap that revokes it and one insert each of the new session
     * and its first proof, reads what was left under the new session's key (two
     * reads, which find nothing) and its proofs once, and reads the identity
     * again once committed, besides reserving and releasing a slot on each of
     * the three counters the first sign-in created.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnAProvenSessionReadsSixTimesAndWritesTheReplacement(): void
    {
        $this->seedIdentity();

        $first = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($first);

        $sessions = $this->sessions();
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $again    = $this->assertQueryBudget(6, 9, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), $context));

        self::assertNotSame($first->record->getKey(), $again->session?->record->getKey());
    }

    /**
     * Starting a session for an externally verified identity reloads it once,
     * writes the session, reads the proofs and the provenance left under its
     * key (none), writes its first proof, reads its proofs once, and reads the
     * identity again once the session is committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartReadsTheIdentityAndItsProofsAndWritesTheSessionAndItsProof(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(5, 2, static fn (): SignInResult => $sessions->start($identity, null, 'sso', self::requestContext()))->isSignedIn());
    }

    /**
     * An external sign-in costs what `start()` does and writes its link's guard
     * and the session's provenance too, and nothing more, the first sign-in
     * through the link and every later one alike: the link contract is the
     * adapter's, and the fake one here reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSignInAlsoWritesItsGuardAndTheProvenance(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();
        $result   = $this->linkedResult($identity, tenantId: 'tenant-3');

        self::assertTrue($this->assertQueryBudget(5, 4, static fn (): SignInResult => $sessions->signInExternally($result, self::requestContext()))->isSignedIn());
        self::assertTrue($this->assertQueryBudget(5, 4, static fn (): SignInResult => $sessions->signInExternally($result, self::requestContext()))->isSignedIn());
    }

    /**
     * An unlinked external result reads and writes nothing: it is refused
     * before the identity is reloaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnlinkedExternalResultCostsNothing(): void
    {
        $sessions = $this->sessions();
        $result   = new ExternalResult('connection-7', self::ISSUER, 'nobody');

        $this->externalLinks();

        self::assertSame(
            FailureReason::EXTERNAL_RESULT_UNLINKED,
            $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->signInExternally($result, self::requestContext()))->reason,
        );
    }

    /**
     * A sign-in that needs a further factor reads the identity once (the check
     * judges the sign-in's own proofs in memory), writes its pending session,
     * reads what an earlier session left under its key (two reads, which find
     * nothing), writes its first proof and reads the identity again once
     * committed, signing no token, besides its limits, whose slots it keeps
     * (the account's as well as the identifier's and the IP address's); looking
     * it up reads the session, its owner, its first factor and the one page of
     * proofs the check judges for what is still outstanding; and satisfying it
     * locks and reads the session and its owner, writes the session's issuance
     * guard (so an issuance of the session that overlaps the proof reads it)
     * and the further factor's proof, reads its first factor and the page of
     * proofs the check judges, activates the session with one update, which is
     * the activation's own guard, reads its proofs for the access token's
     * `auth_time` and `amr`, and gives the three slots back.
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
        $result   = $this->assertQueryBudget(4, 8, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()));

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $sessions   = $this->sessions();

        self::assertNotNull($this->assertQueryBudget(4, 0, static fn (): ?PendingSession => $sessions->pending($credential)));

        $sessions = $this->sessions();
        $proof    = self::proofFor($identity, $result->pending->id);

        self::assertTrue($this->assertQueryBudget(5, 6, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()))->isSignedIn());
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

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $sessions   = $this->sessions('members');

        self::assertNotNull($this->assertQueryBudget(7, 0, static fn (): ?PendingSession => $sessions->pending($credential)));

        $sessions = $this->sessions('members');
        $proof    = self::proofFor($member, $result->pending->id, 'members');

        self::assertTrue($this->assertQueryBudget(8, 6, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()))->isSignedIn());
    }

    /**
     * A pending session whose tenant's policy asks for a further factor reads
     * its first factor once to be looked up and once to be satisfied: the
     * tenant's verdict is judged on it, and the identity's own requirement and
     * the pending session reuse it. Otherwise it costs what a pending session
     * recording a membership costs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionUnderItsTenantsFactorReadsItsFirstFactorOnce(): void
    {
        [$member] = $this->seedMember();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart))));
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $sessions   = $this->sessions('members');

        self::assertNotNull($this->assertQueryBudget(7, 0, static fn (): ?PendingSession => $sessions->pending($credential)));
        self::assertSame(1, $this->firstFactorReads());

        $sessions = $this->sessions('members');
        $proof    = self::proofFor($member, $result->pending->id, 'members');

        self::assertTrue($this->assertQueryBudget(8, 6, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()))->isSignedIn());
        self::assertSame(1, $this->firstFactorReads());
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

        $first = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($first);

        self::requireAFurtherFactor();

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $pending = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $proof      = self::proofFor($identity, $pending->pending->id);
        $sessions   = $this->sessions();
        $result     = $this->assertQueryBudget(6, 7, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()));

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

        $credential = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->credential?->reveal();

        self::assertNotNull($credential);

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(2, 1, static fn (): bool => $sessions->discard($credential, self::requestClient())));
        self::assertFalse($this->assertQueryBudget(1, 0, static fn (): bool => $sessions->discard($credential, self::requestClient())));
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

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $credential = $result->credential->reveal();
        $proof      = self::proofFor($identity, $result->pending->id);

        self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());

        $sessions = $this->sessions();

        self::assertSame(
            FailureReason::PENDING_INVALID,
            $this->assertQueryBudget(1, 0, static fn (): SignInResult => $sessions->satisfy($credential, $proof, self::requestClient()))->reason,
        );
        self::assertSame(
            FailureReason::PENDING_INVALID,
            $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->satisfy('not-a-pending-credential', $proof, self::requestClient()))->reason,
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

        self::assertTrue($this->assertQueryBudget(1, $writes, static fn (): SignInResult => $sessions->signIn('password', $credentials, self::requestContext()))->isFailed());

        $this->useTimebox();

        $sessions = $this->sessions();
        $started  = hrtime(true);

        self::assertTrue($sessions->signIn('password', $credentials, self::requestContext())->isFailed());
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

            self::assertTrue($sessions->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

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
     * Use the real timebox length for the timing contracts.
     *
     * @return void
     */
    private function useTimebox(): void
    {
        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);
    }
}
