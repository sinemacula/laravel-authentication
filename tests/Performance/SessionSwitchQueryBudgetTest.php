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
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
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
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;

/**
 * Query-budget and timing contracts for choosing and switching principal: a
 * sign-in held for a choice reads the identity and its principals (and each
 * one's tenant) and writes the attempt counters and the pending choice; making
 * the choice uses it up, writes the session and gives the slots back; a switch
 * reads the refresh counters, the session, its owner, the target, its tenant
 * and its owner, writes the one compare-and-swap, and then reads the principal
 * it switched from for the event, while a switch its destination's policy
 * returns to pending reads the first factor once instead, a grace retry writes
 * nothing and a refusal writes only the counters.
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
     * A switch to another membership reads the refresh counters, the session,
     * its owner, the target, its tenant and its owner, writes the switch, reads
     * the session's proofs for the new access token, and reads the membership
     * it switched from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsItsReadsAndOneUpdate(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(8, 1, static fn (): SwitchResult => $sessions->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second)));

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch whose destination's tenant now asks for a further factor reads
     * the refresh counters, the session, its owner, the target, its tenant and
     * its owner, then the one first-factor proof the policy is judged on, which
     * the identity's own requirement and the pending session reuse, and writes
     * the one compare-and-swap that returns the session to pending instead of
     * the switch.
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
        $result   = $this->assertQueryBudget(7, 1, static fn (): SwitchResult => $sessions->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second)));

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
        yield 'met by the accepted evidence' => [true, 10];
        yield 'not met by it' => [false, 8];
    }

    /**
     * A switch of a session an external provider established, whose
     * destination's tenant asks for a further factor, reads what a switch
     * returning to pending reads, then the session's accepted evidence in one
     * more read: met, it switches, reading the session's proofs for the new
     * access token and the membership it switched from; not met, it returns the
     * session to pending. Either way it writes one compare-and-swap.
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
        $token    = $session->tokens->refreshToken?->reveal();
        $result   = $this->assertQueryBudget($reads, 1, static fn (): SwitchResult => $sessions->switchTo($token, SwitchTarget::principal($second)));

        self::assertSame([$meets, !$meets], [$result->isSwitched(), $result->isPending()]);
    }

    /**
     * A sign-in held for a choice between two memberships reads the identity,
     * its memberships and each one's tenant, and what an earlier session left
     * under the pending session's key (two reads, which find nothing), and
     * writes the six attempt-counter statements a password sign-in makes, the
     * pending session and its first proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsItsReadsTheCountersAndOneInsert(): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(6, 8, static fn (): SignInResult => $sessions->signIn('password', self::credentials('chooser@example.test')));

        self::assertTrue($result->isPending());
    }

    /**
     * Reading a pending session waiting on a choice reads the session, its
     * identity, the memberships and each one's tenant, and its first factor,
     * and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadingAChoiceIsItsReadsAlone(): void
    {
        $token = $this->offerChoice();

        $sessions = $this->sessions('choosers');
        $choice   = $this->assertQueryBudget(6, 0, static fn (): ?PendingSession => $sessions->pending($token));

        self::assertCount(2, $choice->principals ?? []);
    }

    /**
     * Choosing locks and reads the pending session and its identity, reads the
     * chosen membership, its owner and its tenant, reads its first factor (the
     * default factor policy asks nothing, so no other proof is read), activates
     * the session with one update, reads its proofs, and gives each of the
     * sign-in's three attempt slots back: the session and its first proof were
     * written when the sign-in left it pending.
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
        $result   = $this->assertQueryBudget(7, 4, static fn (): SignInResult => $sessions->choose($token, $chosen));

        self::assertTrue($result->isSignedIn());
    }

    /**
     * Choosing a membership whose tenant's policy asks for a further factor
     * keeps the session pending on it: it locks and reads the session and its
     * identity, reads the chosen membership, its owner and its tenant, and the
     * one first-factor proof the tenant's verdict is judged on, which the
     * identity's own requirement and the pending session reuse, and records the
     * choice and what it now waits on with one update.
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
        $result   = $this->assertQueryBudget(6, 1, static fn (): SignInResult => $sessions->choose($token, $chosen));

        self::assertTrue($result->isPending());
        self::assertSame(1, $this->firstFactorReads());
    }

    /**
     * Choosing the principal of the session the sign-in proved reads what a
     * choice reads and the proven session again on the write connection, and
     * revokes the proven session with one compare-and-swap before the
     * activation's update.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingThePrincipalOfAProvenSessionReplacesIt(): void
    {
        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();
        $first  = $this->sessions('choosers')->choose($token, $chosen)->session;

        self::assertNotNull($first);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $choice  = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'), $context)->credential?->reveal();

        self::assertNotNull($choice);

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(8, 5, static fn (): SignInResult => $sessions->choose($choice, $chosen));

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

        $sessions = self::sessionsOf($this->guardForRequest(['refresh_token' => $session->tokens->refreshToken?->reveal()]));
        $result   = $this->assertQueryBudget(8, 1, static fn (): ?SwitchResult => $sessions->switchFromRequest(SwitchTarget::principal($second)));

        self::assertTrue($result?->isSwitched());
    }

    /**
     * A lost switch response retried inside the grace window reads the refresh
     * counters, the session, its owner, the target, its tenant and its owner,
     * and the session's proofs, and writes nothing: the current credential is
     * handed back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryOfASwitchIsItsReadsAlone(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        self::assertTrue($this->sessions('members')->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->isSwitched());

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(7, 0, static fn (): SwitchResult => $sessions->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second)));

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch to a principal of another identity reads the refresh counters,
     * the session, its owner and the identity's principals, is refused, and
     * writes nothing but the failure on the two refresh counters.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSwitchWritesNothingButTheCounters(): void
    {
        [$session]   = $this->signInWithASecondMembership();
        [, $foreign] = $this->seedMember('other@example.test');

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(5, 4, static fn (): SwitchResult => $sessions->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($foreign)));

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

        self::assertSame(FailureReason::TOKEN_INVALID, $this->sessions('members')->switchTo('not a token', SwitchTarget::principal($second))->reason);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(1, 0, static fn (): SwitchResult => $sessions->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second)));

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
    }

    /**
     * Warmed switches, grace retries and refusals each stay far inside a
     * generous time ceiling, so a pathological regression that adds no query,
     * such as a key derivation per check, still fails.
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

        $token   = $session->tokens->refreshToken?->reveal();
        $targets = [$second, $first];

        self::assertNotNull($this->sessions('members')->switchTo($token, SwitchTarget::principal($foreign))->reason);

        $started = hrtime(true);

        for ($switch = 0; $switch < self::TIMED_SWITCHES; $switch++) {
            $result = $this->sessions('members')->switchTo($token, SwitchTarget::principal($targets[$switch % 2]));

            self::assertTrue($result->isSwitched());

            $token = $result->session?->tokens->refreshToken?->reveal() ?? '';
        }

        $switches = hrtime(true) - $started;
        $previous = $token;

        $this->sessions('members')->switchTo($token, SwitchTarget::principal($targets[0]));

        $started = hrtime(true);

        for ($retry = 0; $retry < self::TIMED_SWITCHES; $retry++) {
            self::assertTrue($this->sessions('members')->switchTo($previous, SwitchTarget::principal($targets[0]))->isSwitched());
        }

        $retries = hrtime(true) - $started;
        $started = hrtime(true);

        for ($refusal = 0; $refusal < self::TIMED_SWITCHES; $refusal++) {
            self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->sessions('members')->switchTo($previous, SwitchTarget::principal($foreign))->reason);
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
     * Persist a chooser with two memberships, each in its own active tenant,
     * sign it in, and return the pending credential its choice waits on.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function offerChoice(): string
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $choice = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'))->credential?->reveal();

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
