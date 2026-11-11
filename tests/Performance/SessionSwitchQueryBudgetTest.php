<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;

/**
 * Query-budget and timing contracts for choosing and switching principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversTrait(SwitchesSessions::class)]
final class SessionSwitchQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var int Switches, grace retries and refusals each timed by the timing contract. */
    private const int TIMED_SWITCHES = 20;

    /** @var int Generous ceiling for each group of them, in nanoseconds (100 ms each). */
    private const int TIMED_CEILING_NANOSECONDS = self::TIMED_SWITCHES * 100000000;

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
     * A switch to another membership costs its reads, its issuance guard and
     * one update.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsItsReadsItsGuardAndOneUpdate(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(
            10,
            2,
            static fn (): SwitchResult => $sessions->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            ),
        );

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch of tenant alone reads the membership again for the tenant
     * switched to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOfTenantAloneReadsThePrincipalAgainForItsTenant(): void
    {
        [, $first, $tenant] = $this->seedMember();

        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);
        $tree       = (new DescendantTenants)->place(self::modelKey($descendant), self::modelKey($tenant));

        app()->instance(TenantAccess::class, $tree);
        app()->instance(TenantResolver::class, $tree);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $sessions = $this->sessions('members');
        $target   = SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant)));
        $result   = $this->assertQueryBudget(
            12,
            2,
            static fn (): SwitchResult => $sessions->switchTo(self::bodyToken($session->tokens), $target, self::requestClient()),
        );

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch its destination's policy returns to pending reads the first
     * factor once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchReturningToPendingReadsItsFirstFactorOnce(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', new Requirement(new RequirementPart))));

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(
            10,
            2,
            static fn (): SwitchResult => $sessions->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            ),
        );

        self::assertTrue($result->isPending());
    }

    /**
     * Rows of `[whether the session's accepted evidence meets the destination
     * tenant's factor, reads]`.
     *
     * @return iterable<string, array{0: bool, 1: int}>
     */
    public static function provideExternalEvidenceVerdicts(): iterable
    {
        yield 'met by the accepted evidence' => [true, 12];
        yield 'not met by it' => [false, 11];
    }

    /**
     * An external session's switch under a tenant's factor reads its accepted
     * evidence once.
     *
     * @param  bool  $meets
     * @param  int  $reads
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExternalEvidenceVerdicts')]
    public function testAnExternalSessionsSwitchUnderATenantsFactorReadsItsAcceptedEvidenceOnce(bool $meets, int $reads): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second   = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $evidence = new ExternalEvidence(['mfa'], null, CarbonImmutable::now());

        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy($meets ? [RequirementKind::MULTIFACTOR] : []));

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, evidence: $evidence), self::asPrincipal($first))->session;

        self::assertNotNull($session);

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart))));

        $sessions = $this->sessions('members');
        $token    = self::bodyRefreshToken($session->tokens);
        $result   = $this->assertQueryBudget(
            $reads,
            2,
            static fn (): SwitchResult => $sessions->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($second), self::requestClient()),
        );

        self::assertSame([$meets, !$meets], [$result->isSwitched(), $result->isPending()]);
    }

    /**
     * Provide how many memberships a choice is offered between.
     *
     * @return iterable<string, array{int}>
     */
    public static function provideMembershipCounts(): iterable
    {
        yield 'two memberships' => [2];
        yield 'five memberships' => [5];
    }

    /**
     * A sign-in held for a choice costs its reads, its counters and the pending
     * session's insert.
     *
     * @param  int  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMembershipCounts')]
    public function testAChoiceIsItsReadsTheCountersAndOneInsert(int $memberships): void
    {
        $this->seedChooser($memberships);

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(6, 8, static fn (): SignInResult => $sessions->signIn('password', self::credentials('chooser@example.test'), self::requestContext()));

        self::assertTrue($result->isPending());
    }

    /**
     * Reading a pending choice reads the tenants once however many memberships,
     * and writes nothing.
     *
     * @param  int  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMembershipCounts')]
    public function testReadingAChoiceIsItsReadsAlone(int $memberships): void
    {
        $token = $this->offerChoice($memberships);

        $sessions = $this->sessions('choosers');
        $choice   = $this->assertQueryBudget(5, 0, static fn (): ?PendingSession => $sessions->pending($token));

        self::assertCount($memberships, $choice->principals ?? []);
    }

    /**
     * A sign-in selecting one of several memberships reads their tenants once.
     *
     * @param  int  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMembershipCounts')]
    public function testASignInSelectingOneOfSeveralMembershipsReadsTheirTenantsOnce(int $memberships): void
    {
        $this->seedChooser($memberships);

        ActivatableTenant::query()->where('name', '!=', 'Tenant 1')->update(['is_active' => false]);

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(9, 11, static fn (): SignInResult => $sessions->signIn('password', self::credentials('chooser@example.test'), self::requestContext()));

        self::assertTrue($result->isSignedIn());
    }

    /**
     * Choosing activates the session with one update and gives the sign-in's
     * slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingIsItsReadsTheSessionAndTheSlotsGivenBack(): void
    {
        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(9, 4, static fn (): SignInResult => $sessions->choose($token, $chosen, self::requestClient()));

        self::assertTrue($result->isSignedIn());
    }

    /**
     * A choice given a same-site client costs what a choice without a client
     * does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingForASameSiteClientGivenCostsWhatChoosingCosts(): void
    {
        config()->set('auth.guards.choosers.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();

        request()->headers->set('Origin', 'https://evil.example.test');
        request()->headers->remove('X-Requested-With');

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(9, 4, static fn (): SignInResult => $sessions->choose($token, $chosen, self::sameSiteClient()));

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session?->tokens->refreshCookie);
    }

    /**
     * Choosing into a tenant's further factor reads its first factor once and
     * keeps the session pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingIntoATenantsFurtherFactorReadsItsFirstFactorOnce(): void
    {
        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart))));

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(8, 1, static fn (): SignInResult => $sessions->choose($token, $chosen, self::requestClient()));

        self::assertTrue($result->isPending());
        self::assertSame(1, $this->firstFactorReads());
    }

    /**
     * Choosing the proven session's principal revokes that session with one
     * compare-and-swap.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingThePrincipalOfAProvenSessionReplacesIt(): void
    {
        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();
        $first  = $this->sessions('choosers')->choose($token, $chosen, self::requestClient())->session;

        self::assertNotNull($first);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $choice  = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'), $context)->credential?->reveal();

        self::assertNotNull($choice);

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(10, 5, static fn (): SignInResult => $sessions->choose($choice, $chosen, self::requestClient()));

        self::assertNotSame($first->record->getKey(), $result->session?->record->getKey());
        self::assertSame('superseded', Session::query()->whereKey($first->record->getKey())->value('revoked_reason'));
    }

    /**
     * A switch whose refresh token the request carries costs what a switch
     * costs: reading the token from the request runs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchFromTheRequestCostsWhatASwitchCosts(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        $sessions = self::sessionsOf($this->guardForRequest(['refresh_token' => self::bodyRefreshToken($session->tokens)]));
        $result   = $this->assertQueryBudget(
            10,
            2,
            static fn (): ?SwitchResult => $sessions->switchTo(self::servedToken('members'), SwitchTarget::principal($second), self::requestClient()),
        );

        self::assertTrue($result?->isSwitched());
    }

    /**
     * A grace retry of a switch writes nothing but the issuance guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryOfASwitchIsItsReadsAndItsGuard(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        self::assertTrue(
            $this->sessions('members')->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->isSwitched(),
        );

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(
            8,
            1,
            static fn (): SwitchResult => $sessions->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            ),
        );

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch to another identity's principal is refused, writing only its
     * guard and the counters.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSwitchWritesNothingButItsGuardAndTheCounters(): void
    {
        [$session]   = $this->signInWithASecondMembership();
        [, $foreign] = $this->seedMember('other@example.test');

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(
            6,
            5,
            static fn (): SwitchResult => $sessions->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($foreign),
                self::requestClient(),
            ),
        );

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $result->reason);
    }

    /**
     * A switch the refresh limits already refuse reads the counters and nothing
     * else: neither the session nor the target is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedSwitchIsRefusedFromTheLimitsAlone(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        config()->set('auth.guards.members.rate_limits', ['refresh' => ['per_identifier' => null, 'per_ip' => ['max' => 1, 'decay_seconds' => 60]]]);

        self::assertSame(
            FailureReason::TOKEN_INVALID,
            $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody('not a token'), SwitchTarget::principal($second), self::requestClient())->reason,
        );

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(
            1,
            0,
            static fn (): SwitchResult => $sessions->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            ),
        );

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
    }

    /**
     * Warmed switches, retries and refusals each stay within a generous time
     * ceiling.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchesRetriesAndRefusalsStayWithinAGenerousTimeCeiling(): void
    {
        $limit = ['max' => 1000, 'decay_seconds' => 60];

        config()->set('auth.guards.members.rate_limits', ['refresh' => ['per_identifier' => $limit, 'per_ip' => $limit]]);

        [$session, $second, $first] = $this->signInWithASecondMembership();
        [, $foreign]                = $this->seedMember('other@example.test');

        $token   = self::bodyRefreshToken($session->tokens);
        $targets = [$second, $first];

        self::assertNotNull($this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($foreign), self::requestClient())->reason);

        $started = hrtime(true);

        for ($switch = 0; $switch < self::TIMED_SWITCHES; $switch++) {
            $result = $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($targets[$switch % 2]), self::requestClient());

            self::assertTrue($result->isSwitched());

            $token = $result->session?->tokens->refreshToken?->reveal() ?? '';
        }

        $switches = hrtime(true) - $started;
        $previous = $token;

        $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($targets[0]), self::requestClient());

        $started = hrtime(true);

        for ($retry = 0; $retry < self::TIMED_SWITCHES; $retry++) {
            self::assertTrue(
                $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($previous), SwitchTarget::principal($targets[0]), self::requestClient())->isSwitched(),
            );
        }

        $retries = hrtime(true) - $started;
        $started = hrtime(true);

        for ($refusal = 0; $refusal < self::TIMED_SWITCHES; $refusal++) {
            self::assertSame(
                FailureReason::PRINCIPAL_MISMATCH,
                $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($previous), SwitchTarget::principal($foreign), self::requestClient())->reason,
            );
        }

        $refusals = hrtime(true) - $started;

        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $switches);
        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $retries);
        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $refusals);
    }

    /**
     * Register the session guards, and a guard over the choosing members.
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

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
    }

    /**
     * Persist a chooser with the given number of memberships, each in its own
     * active tenant.
     *
     * @param  int  $memberships
     * @return void
     */
    private function seedChooser(int $memberships): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (range(1, $memberships) as $index) {
            $tenant = ActivatableTenant::query()->create(['name' => 'Tenant ' . $index, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }
    }

    /**
     * Persist a chooser with that many memberships, sign it in and return the
     * credential its choice waits on.
     *
     * @param  int  $memberships
     * @return string
     *
     * @throws \Throwable
     */
    private function offerChoice(int $memberships = 2): string
    {
        $this->seedChooser($memberships);

        $choice = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'), self::requestContext())->credential?->reveal();

        self::assertNotNull($choice);

        return $choice;
    }

    /**
     * Persist a member with its default membership and a second one in the same
     * tenant, and sign it in as the default.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\SignedInSession, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function signInWithASecondMembership(): array
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        return [$session, $second, $first];
    }

    /**
     * The `members` guard, resolved afresh for a request with the body.
     *
     * @param  array<string, string>  $body
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardForRequest(array $body): JwtGuard
    {
        app()->instance('request', Request::create('/switch', 'POST', $body, server: ['REMOTE_ADDR' => self::CLIENT_IP]));

        return $this->freshJwtGuard('members');
    }
}
