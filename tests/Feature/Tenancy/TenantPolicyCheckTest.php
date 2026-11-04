<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\TestCase;

/**
 * Feature tests for judging a session, or a sign-in's evidence, against its
 * tenant's authentication policy, with a scripted policy and check, against
 * sessions and proofs in a real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyCheck::class)]
#[CoversClass(SessionProofs::class)]
final class TenantPolicyCheckTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy the tenant answers with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /** @var \Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck The check judging further factors. */
    private ProofJudgingRequirementCheck $check;

    /**
     * Create the tables and bind the scripted policy and check.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        $this->policy = new ScriptedTenantAuthenticationPolicy;
        $this->check  = new ProofJudgingRequirementCheck;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);
        app()->instance(RequirementCheck::class, $this->check);
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
     * A destination of no tenant has no policy: it is met, with no version, and
     * the policy is never asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationOfNoTenantMeetsNoPolicy(): void
    {
        [$member, $membership] = $this->seedMember();

        $verdict = TenantPolicyCheck::check('members', $member, $membership, null, null, CarbonImmutable::now());

        self::assertSame(TenantPolicyStanding::MET, $verdict->standing);
        self::assertNull($verdict->version);
        self::assertSame([], $this->policy->asked);
    }

    /**
     * The policy is asked about the application, the identity, the principal,
     * the tenant and the session, and its version is passed through; an answer
     * that asks for nothing reads neither provenance nor proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAnswerAskingNothingIsMetWithoutReadingTheSession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->policy->requirement = new TenantRequirement('v7');

        $asked = count($this->policy->asked);

        DB::enableQueryLog();

        $verdict = TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, CarbonImmutable::now());

        self::assertSame([], DB::getQueryLog());
        self::assertSame(TenantPolicyStanding::MET, $verdict->standing);
        self::assertSame('v7', $verdict->version);
        self::assertNull($verdict->firstFactor);

        $context = $this->policy->asked[$asked] ?? null;

        self::assertNotNull($context);

        self::assertSame('members', $context->application);
        self::assertSame($member, $context->identity);
        self::assertSame($membership, $context->principal);
        self::assertSame($tenant, $context->tenant);
        self::assertSame($session, $context->session);
    }

    /**
     * Named connections are met only by a session established through one of
     * them, as its provenance records; a session no provider established, an
     * empty list, and no session at all meet none, and a verdict that requires
     * a connection names no further factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testConnectionsAreMetOnlyByASessionEstablishedThroughOne(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $password = $this->signedIn();
        $external = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a'), self::asPrincipal($membership))->session?->record;

        self::assertNotNull($external);

        $standing = fn (?Session $session): TenantPolicyStanding => TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, CarbonImmutable::now())->standing;

        $this->policy->requirement = new TenantRequirement(connections: ['conn-a']);

        self::assertSame(TenantPolicyStanding::MET, $standing($external));
        self::assertSame(TenantPolicyStanding::SSO_REQUIRED, $standing($password));

        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart), connections: ['conn-a']);

        $refused = TenantPolicyCheck::check('members', $member, $membership, $tenant, $password, CarbonImmutable::now());

        self::assertTrue($refused->factor->isEmpty());
        self::assertNull($refused->firstFactor);

        $this->policy->requirement = new TenantRequirement(connections: ['conn-a']);

        self::assertSame(TenantPolicyStanding::SSO_REQUIRED, $standing(null));

        $this->policy->requirement = new TenantRequirement(connections: []);

        self::assertSame(TenantPolicyStanding::SSO_REQUIRED, $standing($external));
    }

    /**
     * A sign-in's own evidence decides the connection, without reading the
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsEvidenceDecidesTheConnection(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->policy->requirement = new TenantRequirement(connections: ['conn-a']);

        $now      = CarbonImmutable::now();
        $external = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a'), $now));
        $password = SessionEvidence::of(SignInProof::unattested('password', $now));

        DB::enableQueryLog();

        self::assertTrue(TenantPolicyCheck::check('members', $member, $membership, $tenant, null, $now, new ProofSource($external))->isMet());
        self::assertSame(TenantPolicyStanding::SSO_REQUIRED, TenantPolicyCheck::check('members', $member, $membership, $tenant, null, $now, new ProofSource($password))->standing);
        self::assertSame([], DB::getQueryLog());
    }

    /**
     * A requirement already answered is judged as `check()` judges the policy's
     * answer, without asking the policy: against the sign-in's evidence, its
     * version carried on the verdict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAnsweredRequirementIsJudgedWithoutAskingThePolicy(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $now      = CarbonImmutable::now();
        $answered = new TenantRequirement('v3', connections: ['conn-a']);
        $external = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a'), $now));
        $password = SessionEvidence::of(SignInProof::unattested('password', $now));

        $this->policy->requirement = new TenantRequirement(connections: ['conn-b']);

        $met     = TenantPolicyCheck::judge($answered, $tenant, 'members', $member, null, $now, new ProofSource($external));
        $refused = TenantPolicyCheck::judge($answered, $tenant, 'members', $member, null, $now, new ProofSource($password));

        self::assertSame([TenantPolicyStanding::MET, 'v3'], [$met->standing, $met->version]);
        self::assertSame([TenantPolicyStanding::SSO_REQUIRED, 'v3'], [$refused->standing, $refused->version]);
    }

    /**
     * A further factor is met only when the bound check finds it met against
     * the session's counting proofs, read newest first, with the first factor
     * at hand; never by the default check, and never without a session or
     * evidence. A verdict that falls short of it names the requirement, and one
     * that meets it names none; either carries the first factor it was judged
     * on, read once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherFactorIsMetOnlyAsTheCheckJudgesIt(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $now     = CarbonImmutable::now();

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart(600)));

        DB::enableQueryLog();

        $verdict = TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now);
        $reads   = array_filter(DB::getQueryLog(), static fn (array $query): bool => preg_match('/[`"]kind[`"] = \?/', $query['query']) === 1);

        DB::disableQueryLog();

        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, $verdict->standing);
        self::assertSame('v2', $verdict->version);
        self::assertSame($this->policy->requirement->factor, $verdict->factor);
        self::assertCount(1, $reads);

        $subject = $this->check->judged[0];

        self::assertSame($subject->firstFactor, $verdict->firstFactor);
        self::assertSame(ProofKind::FIRST_FACTOR, $subject->firstFactor->kind);
        self::assertSame($session, $subject->session);
        self::assertSame('members', $subject->application);

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $now, ['otp'], new Evaluation(true, true));

        $met = TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now);

        self::assertTrue($met->isMet());
        self::assertTrue($met->factor->isEmpty());
        self::assertSame($this->check->judged[1]->firstFactor, $met->firstFactor);
        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, TenantPolicyCheck::check('members', $member, $membership, $tenant, null, $now)->standing);

        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now)->standing);
    }

    /**
     * A check made under the session's lock reads its provenance and proofs
     * current: the connection, the first factor, the accepted evidence and the
     * check's proofs, each with a shared lock where the engine takes one,
     * through `check()` and `judge()` alike; a plain check takes none, and a
     * policy that asks for nothing reads nothing either way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACheckUnderTheLockReadsTheProvenanceAndProofsCurrent(): void
    {
        self::markSharedLocks();

        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a'), self::asPrincipal($membership))->session?->record;
        $now     = CarbonImmutable::now();

        self::assertNotNull($session);

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart), ['conn-a']);

        $checked = static fn (ProofSource $source): TenantPolicyVerdict => TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now, $source);
        $judged  = fn (ProofSource $source): TenantPolicyVerdict => TenantPolicyCheck::judge($this->policy->requirement, $tenant, 'members', $member, $session, $now, $source);
        $check   = static fn (ProofSource $source): array => self::proofReadLocks(static fn (): mixed => $checked($source));
        $judge   = static fn (ProofSource $source): array => self::proofReadLocks(static fn (): mixed => $judged($source));

        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, $checked(new ProofSource(current: true))->standing);

        self::assertSame(array_fill(0, 4, self::takesSharedLocks()), $check(new ProofSource(current: true)));
        self::assertSame(array_fill(0, 4, self::takesSharedLocks()), $judge(new ProofSource(current: true)));
        self::assertSame(array_fill(0, 4, false), $check(new ProofSource));
        self::assertSame(array_fill(0, 4, false), self::proofReadLocks(static fn (): mixed => TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now)));

        $this->policy->requirement = new TenantRequirement('v2');

        self::assertSame([], $check(new ProofSource(current: true)));
    }

    /**
     * A sign-in's evidence is read in place of the session's stored proofs when
     * both are given: a further factor the session stores does not meet a
     * requirement the sign-in's own proofs do not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsEvidenceIsReadOverTheSessionsProofs(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $now     = CarbonImmutable::now();

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $now, ['otp'], new Evaluation(true, true));

        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart));

        self::assertTrue(TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now)->isMet());

        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        $judged = TenantPolicyCheck::check('members', $member, $membership, $tenant, $session, $now, new ProofSource($evidence));

        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, $judged->standing);
        self::assertSame([$evidence->firstFactor], $this->check->judged[1]->proofs());
    }

    /**
     * A tenant's further factor is met by a sign-in through one of its
     * connections whose evidence the evidence policy accepted and says meets
     * it, with no further factor proved; not by the default evidence policy,
     * which leaves it to the check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsFurtherFactorIsMetByAcceptedEvidence(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $now      = CarbonImmutable::now();
        $accepted = new ExternalEvidence(['hwk'], 'phrh', $now);
        $evidence = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $accepted), $now, new Evaluation(true, true)));

        $this->policy->requirement = new TenantRequirement('v4', new Requirement(multifactor: new RequirementPart), ['conn-a']);

        $judged = TenantPolicyCheck::check('members', $member, $membership, $tenant, null, $now, new ProofSource($evidence));

        self::assertSame(TenantPolicyStanding::FACTOR_REQUIRED, $judged->standing);
        self::assertCount(1, $this->check->judged);

        $policy = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        $verdict = TenantPolicyCheck::check('members', $member, $membership, $tenant, null, $now, new ProofSource($evidence));

        self::assertSame([TenantPolicyStanding::MET, 'v4'], [$verdict->standing, $verdict->version]);
        self::assertSame($accepted, $policy->asked[0]['evidence']);
        self::assertSame([$tenant, 'conn-a'], [$policy->asked[0]['subject']->tenant, $policy->asked[0]['subject']->connectionId]);
        self::assertCount(1, $this->check->judged);
    }

    /**
     * What a tenant requires is the policy's answer, asked about the guard,
     * identity, principal, tenant and session given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRequirementIsThePolicysAnswerForTheSession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->policy->requirement = new TenantRequirement('v7', connections: ['conn-a']);

        $before      = count($this->policy->asked);
        $requirement = TenantPolicyCheck::requirementFor('members', $member, $membership, $tenant, $session);
        $asked       = array_slice($this->policy->asked, $before);

        self::assertSame($this->policy->requirement, $requirement);
        self::assertCount(1, $asked);
        self::assertSame('members', $asked[0]->application);
        self::assertSame($member, $asked[0]->identity);
        self::assertSame($membership, $asked[0]->principal);
        self::assertSame($tenant, $asked[0]->tenant);
        self::assertSame($session, $asked[0]->session);
    }

    /**
     * The check is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TenantPolicyCheck::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TenantPolicyCheck::class, $instance);
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
     * Sign the seeded member in with its password and return its session.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(): Session
    {
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }
}
