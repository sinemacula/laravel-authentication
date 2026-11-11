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
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;

/**
 * Query-budget and timing contracts for the session service's sign-ins.
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
     * A sign-in on a new session reads five times and writes the session, its
     * first proof and its limits.
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
     * Inside a caller's transaction a sign-in costs one read more, at the
     * commit.
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
     * A cookie application's sign-in costs what a body application's does.
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

        $result = $this->assertQueryBudget(0, 0, static fn (): SignInResult => $sessions->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext()));

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $result->reason);
    }

    /**
     * A cookie application's pending actions from another site are refused
     * before any query.
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
     * A satisfaction given a same-site client costs what one from a same-site
     * request does.
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
     * A sign-in on a proven session reads six times and writes the replacement.
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
     * `start()` reads the identity and its proofs and writes the session and
     * its first proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartReadsTheIdentityAndItsProofsAndWritesTheSessionAndItsProof(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        $factor = UndescribedFirstFactor::of($identity);

        self::assertTrue($this->assertQueryBudget(5, 2, static fn (): SignInResult => $sessions->start($factor, null, 'sso', self::requestContext()))->isSignedIn());
    }

    /**
     * An external sign-in costs what `start()` does plus its link's guard and
     * the provenance.
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
     * A pending session costs two writes to sign in and keeps its slots until
     * it activates.
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
     * A pending session recording a membership costs three reads more: the
     * membership, its owner and its tenant.
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
     * A pending session under its tenant's factor reads its first factor once
     * to look it up and once to satisfy it.
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
     * once more and revokes it.
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
     * Satisfying with a credential that names no pending session costs at most
     * one read and writes nothing.
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
     * Rows of `[credentials, writes]`: failed sign-ins and the reservation
     * writes each keeps.
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
     * A failed sign-in reads once, writes only its limits and waits out the
     * timebox.
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
     * A successful sign-in returns before the timebox.
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
