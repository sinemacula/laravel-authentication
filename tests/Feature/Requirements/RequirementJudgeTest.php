<?php

declare(strict_types = 1);

namespace Tests\Feature\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Feature tests for judging a session, or a sign-in's evidence, against a
 * requirement through the bound requirement check, against sessions and proofs
 * in a real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementJudge::class)]
final class RequirementJudgeTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var \Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck The check judging further factors. */
    private ProofJudgingRequirementCheck $check;

    /**
     * Create the tables and bind the proof-judging check.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        $this->check = new ProofJudgingRequirementCheck;

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
     * A requirement that asks for nothing is met by any session, or none,
     * without a query and without asking the check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementAskingNothingIsMetWithoutAQuery(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();

        DB::enableQueryLog();

        self::assertTrue(RequirementJudge::isMet('members', $member, $session, null, CarbonImmutable::now(), null, new Requirement));
        self::assertTrue(RequirementJudge::isMet('members', $member, null, null, CarbonImmutable::now(), null, new Requirement));
        self::assertSame([], DB::getQueryLog());
        self::assertSame([], $this->check->judged);
    }

    /**
     * Against a stored session the check judges its counting proofs, read on
     * the write connection, with the first factor it records at hand: met once
     * it holds an accepted further factor, never by the default check, and
     * judged about the identity, the application and the time given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoredSessionIsJudgedOnItsOwnProofs(): void
    {
        [$member] = $this->seedMember();

        $session     = $this->signedIn();
        $now         = CarbonImmutable::now();
        $requirement = new Requirement(new RequirementPart(600));

        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, $now, null, $requirement));

        [$subject] = $this->check->judged;

        self::assertSame($member, $subject->identity);
        self::assertSame('members', $subject->application);
        self::assertSame($session, $subject->session);
        self::assertSame($now, $subject->now);
        self::assertSame(ProofKind::FIRST_FACTOR, $subject->firstFactor->kind);

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $now, ['otp'], new Evaluation(true, true));

        self::assertTrue(RequirementJudge::isMet('members', $member, $session, null, $now, null, $requirement));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], array_column($this->check->judged[1]->proofs(null, null, 2), 'kind'));

        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, $now, null, $requirement));
    }

    /**
     * The first factor given is the subject's, over the evidence's and the
     * session's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFactorGivenIsTheSubjects(): void
    {
        [$member] = $this->seedMember();

        $session  = $this->signedIn();
        $now      = CarbonImmutable::now();
        $given    = SignInProof::unattested('sso', $now)->recorded();
        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        RequirementJudge::isMet('members', $member, $session, $given, $now, null, new Requirement(new RequirementPart));
        RequirementJudge::isMet('members', $member, null, $given, $now, $evidence, new Requirement(new RequirementPart));

        self::assertSame($given, $this->check->judged[0]->firstFactor);
        self::assertSame($given, $this->check->judged[1]->firstFactor);
    }

    /**
     * The first factor a judgement is made on is the one given, else the
     * evidence's, else the one the session records, read once and only then;
     * with none of them there is none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFactorIsTheGivenElseTheEvidencesElseTheSessions(): void
    {
        $this->seedMember();

        $session  = $this->signedIn();
        $now      = CarbonImmutable::now();
        $given    = SignInProof::unattested('sso', $now)->recorded();
        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        self::assertSame($given, RequirementJudge::firstFactor($session, $given, $evidence));
        self::assertSame($evidence->firstFactor, RequirementJudge::firstFactor($session, null, $evidence));
        self::assertNull(RequirementJudge::firstFactor(null, null, null));
        self::assertCount(0, $statements);

        $recorded = RequirementJudge::firstFactor($session, null, null);

        self::assertSame([ProofKind::FIRST_FACTOR, 'password'], [$recorded?->kind, $recorded?->method]);
        self::assertCount(1, $statements);
    }

    /**
     * A sign-in's evidence is judged in memory, filtered by time to the second,
     * as the stored proofs' query binds it, and by kind and cut to the limit,
     * newest first, and the session not at all: a sign-in half a second into
     * its second proves its first factor in that second, which a requirement
     * asking from the sign-in's own time counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsEvidenceIsJudgedInMemory(): void
    {
        [$member] = $this->seedMember();

        $now      = CarbonImmutable::now()->startOfSecond()->addMilliseconds(500);
        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        DB::enableQueryLog();

        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $evidence, new Requirement(new RequirementPart)));
        self::assertSame([], DB::getQueryLog());

        [$subject] = $this->check->judged;

        self::assertNull($subject->session);
        self::assertSame($evidence->firstFactor, $subject->firstFactor);
        self::assertSame([$evidence->firstFactor], $subject->proofs());
        self::assertSame([$evidence->firstFactor], $subject->proofs($now, [ProofKind::FIRST_FACTOR], 1));
        self::assertSame([], $subject->proofs($now->addSecond()));
        self::assertSame([], $subject->proofs(null, [ProofKind::ADDITIONAL_FACTOR]));

        $first  = SignInProof::unattested('password', $now)->recorded();
        $newest = SignInProof::unattested('password', $now)->recorded();

        RequirementJudge::isMet('members', $member, null, null, $now, new SessionEvidence($first, [$newest, $first], null), new Requirement(new RequirementPart));

        self::assertSame([$newest], $this->check->judged[1]->proofs(null, null, 1));
        self::assertSame([$newest, $first], $this->check->judged[1]->proofs(null, null, 2));
    }

    /**
     * A sign-in's evidence is judged in place of the session's stored proofs
     * when both are given: a further factor the session stores does not meet a
     * requirement the sign-in's own proofs do not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsEvidenceIsJudgedOverTheSessionsProofs(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();
        $now     = CarbonImmutable::now();

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $now, ['otp'], new Evaluation(true, true));

        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        self::assertTrue(RequirementJudge::isMet('members', $member, $session, null, $now, null, new Requirement(new RequirementPart)));
        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, $now, $evidence, new Requirement(new RequirementPart)));
        self::assertSame([$evidence->firstFactor], $this->check->judged[1]->proofs());
    }

    /**
     * With a first factor but neither a session nor evidence the subject has no
     * proofs to read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNeitherSessionNorEvidenceThereAreNoProofs(): void
    {
        [$member] = $this->seedMember();

        $first = SignInProof::unattested('password', CarbonImmutable::now())->recorded();

        self::assertFalse(RequirementJudge::isMet('members', $member, null, $first, CarbonImmutable::now(), null, new Requirement(new RequirementPart)));
        self::assertSame([], $this->check->judged[0]->proofs());
    }

    /**
     * A session that records no first factor, and no session and no evidence at
     * all, meets no requirement that asks for something, and the check is never
     * asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAFirstFactorNothingIsMet(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_proofs')->delete();

        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, CarbonImmutable::now(), null, new Requirement(new RequirementPart)));
        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, CarbonImmutable::now(), null, new Requirement(new RequirementPart)));
        self::assertSame([], $this->check->judged);
    }

    /**
     * The judge is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(RequirementJudge::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(RequirementJudge::class, $instance);
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
