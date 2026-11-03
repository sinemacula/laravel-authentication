<?php

declare(strict_types = 1);

namespace Tests\Feature\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\MethodTrustingEvidencePolicy;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Feature tests for judging a session, or a sign-in's evidence, against a
 * requirement through the bound evidence policy, for accepted external
 * evidence, and the bound requirement check, against sessions and proofs in a
 * real database.
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
     * A sign-in an external provider established, holding evidence the evidence
     * contract accepted, meets a requirement in memory when the evidence policy
     * says that evidence meets the whole of it, asked once with the whole
     * requirement about the identity, the application, the connection and the
     * time, with reads pinned to the write connection, the evidence judged as
     * of now; the requirement check is never asked and nothing is read. When
     * the policy finds it short, the check judges the proofs instead: evidence
     * never meets part of a requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptedEvidenceMeetsTheWholeRequirementInMemory(): void
    {
        [$member] = $this->seedMember();

        $now         = CarbonImmutable::now()->startOfSecond();
        $policy      = $this->trustEvidenceFor([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MULTIFACTOR]);
        $accepted    = new ExternalEvidence(['hwk'], 'phrh', $now->addMinute());
        $evidence    = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $accepted), $now, new Evaluation(true, true)));
        $requirement = new Requirement(new RequirementPart, new RequirementPart(600));

        DB::enableQueryLog();

        self::assertTrue(RequirementJudge::isMet('members', $member, null, null, $now, $evidence, $requirement));
        self::assertSame([], DB::getQueryLog());
        self::assertSame(0, $this->judgedCount());

        [$asked] = $policy->asked;

        self::assertSame($requirement, $asked['requirement']);
        $subject = $asked['subject'];

        self::assertSame([$member, 'members', 'conn-a', $now], [$subject->identity, $subject->application, $subject->connectionId, $subject->now]);
        self::assertSame([['hwk'], $now->getTimestamp()], [$asked['evidence']->methods, $asked['evidence']->authenticatedAt->getTimestamp()]);
        self::assertTrue($asked['pinned']);

        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $evidence, new Requirement(new RequirementPart, phishingResistance: new RequirementPart)));
        self::assertCount(2, $policy->asked);
        self::assertSame(1, $this->judgedCount());
    }

    /**
     * Without accepted evidence the evidence policy is never asked: not for a
     * sign-in an external provider established whose evidence was not accepted,
     * nor for one no provider established, which the requirement check alone
     * judges. By default no evidence meets anything, so the check judges every
     * requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAcceptedEvidenceTheCheckAloneJudges(): void
    {
        [$member] = $this->seedMember();

        $now         = CarbonImmutable::now();
        $policy      = $this->trustEvidenceFor([RequirementKind::ADDITIONAL_VERIFICATION]);
        $requirement = new Requirement(new RequirementPart);

        $unaccepted = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a'), $now));
        $password   = SessionEvidence::of(SignInProof::unattested('password', $now));

        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $unaccepted, $requirement));
        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $password, $requirement));
        self::assertCount(0, $policy->asked);
        self::assertSame(2, $this->judgedCount());

        app()->instance(ExternalEvidencePolicy::class, new InsufficientEvidence);

        $accepted = new ExternalEvidence(['hwk'], null, $now);
        $evidence = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $accepted), $now, new Evaluation(true, false)));

        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $evidence, $requirement));
        self::assertSame(3, $this->judgedCount());
    }

    /**
     * A stored session an external provider established is judged on the
     * evidence its proofs hold accepted, the newest by its own time first (and
     * no further once it meets), read in one more query; a session no provider
     * established reads no evidence and never asks the policy: its first factor
     * and the check's proofs are all it reads.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoredExternalSessionIsJudgedOnItsAcceptedEvidenceNewestFirst(): void
    {
        [$member] = $this->seedMember();

        $now      = CarbonImmutable::now()->startOfSecond();
        $policy   = $this->trustEvidenceFor([RequirementKind::MULTIFACTOR]);
        $password = $this->signedIn();
        $session  = $this->signedIn();
        $older    = new ExternalEvidence(['pwd'], null, $now->subMinutes(5));
        $newest   = new ExternalEvidence(['hwk'], 'phrh', $now->subMinute());

        DB::table('authentication_proofs')->where('session_id', IdentifierCoercion::stringify($session->getKey()))->delete();

        self::recordExternal($session, ProofKind::FIRST_FACTOR, $now->subMinutes(5), $older);
        self::recordExternal($session, ProofKind::EXTERNAL_REAUTHENTICATION, $now->subMinutes(2), $newest);

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        self::assertTrue(RequirementJudge::isMet('members', $member, $session, null, $now, null, new Requirement(multifactor: new RequirementPart)));
        self::assertCount(2, $statements);
        self::assertEquals($newest, $policy->asked[0]['evidence']);
        self::assertSame('conn-a', $policy->asked[0]['subject']->connectionId);
        self::assertSame(0, $this->judgedCount());

        $statements->exchangeArray([]);

        self::assertFalse(RequirementJudge::isMet('members', $member, $password, null, $now, null, new Requirement(multifactor: new RequirementPart)));
        self::assertCount(2, $statements);
        self::assertStringNotContainsString('evidence', implode(' ', $statements->getArrayCopy()));
        self::assertCount(1, $policy->asked);
        self::assertSame(1, $this->judgedCount());
    }

    /**
     * Newer evidence the policy accepted for less never hides older evidence
     * that still meets the requirement: the policy is asked of the newest first
     * and then of the older, which meets it; evidence none of which meets it is
     * refused once each has been asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOlderAcceptedEvidenceStillMeetsWhenNewerFallsShort(): void
    {
        [$member] = $this->seedMember();

        $now     = CarbonImmutable::now()->startOfSecond();
        $session = $this->signedIn();
        $policy  = new MethodTrustingEvidencePolicy(['mfa' => [RequirementKind::MULTIFACTOR], 'hwk' => [RequirementKind::PHISHING_RESISTANCE]]);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        DB::table('authentication_proofs')->where('session_id', IdentifierCoercion::stringify($session->getKey()))->delete();

        self::recordExternal($session, ProofKind::FIRST_FACTOR, $now->subMinutes(5), new ExternalEvidence(['mfa'], null, $now->subMinutes(5)));
        self::recordExternal($session, ProofKind::EXTERNAL_REAUTHENTICATION, $now->subMinute(), new ExternalEvidence(['hwk'], null, $now->subMinute()));

        self::assertTrue(RequirementJudge::isMet('members', $member, $session, null, $now, null, new Requirement(multifactor: new RequirementPart)));
        self::assertSame([['hwk'], ['mfa']], $policy->judged);
        self::assertSame(0, $this->judgedCount());

        $policy->judged = [];

        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, $now, null, new Requirement(additionalVerification: new RequirementPart)));
        self::assertSame([['hwk'], ['mfa']], $policy->judged);
    }

    /**
     * The requirement check never sees an external proof's acceptance, stored
     * or in memory: provider multifactor evidence three days old, which the
     * evidence policy finds too old for a five-minute requirement, reaches the
     * check as proofs with no evaluation, so a check counting accepted
     * multifactor proofs cannot credit it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCheckSeesNoExternalProofsAcceptance(): void
    {
        [$member] = $this->seedMember();

        $now         = CarbonImmutable::now()->startOfSecond();
        $stale       = new ExternalEvidence(['mfa'], null, $now->subDays(3));
        $session     = $this->signedIn();
        $requirement = new Requirement(multifactor: new RequirementPart(300));

        $this->trustEvidenceFor([]);

        DB::table('authentication_proofs')->where('session_id', IdentifierCoercion::stringify($session->getKey()))->delete();

        self::recordExternal($session, ProofKind::FIRST_FACTOR, $now, $stale);

        $signIn = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $stale), $now, new Evaluation(true, true)));

        self::assertFalse(RequirementJudge::isMet('members', $member, $session, null, $now, null, $requirement));
        self::assertFalse(RequirementJudge::isMet('members', $member, null, null, $now, $signIn, $requirement));
        self::assertSame(2, $this->judgedCount());

        foreach ($this->check->judged as $subject) {
            $proofs = $subject->proofs();

            self::assertCount(1, $proofs);
            self::assertSame([null, null], [$subject->firstFactor->evaluation, $proofs[0]->evaluation]);
            self::assertEquals($stale, $proofs[0]->evidence);
        }
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
     * How many subjects the requirement check has judged so far.
     *
     * @return int
     */
    private function judgedCount(): int
    {
        return count($this->check->judged);
    }

    /**
     * Bind an evidence policy that trusts a provider's evidence for the kinds
     * given.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $trusted
     * @return \Tests\Fixtures\External\ScriptedEvidencePolicy
     */
    private function trustEvidenceFor(array $trusted): ScriptedEvidencePolicy
    {
        $policy = new ScriptedEvidencePolicy($trusted);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        return $policy;
    }

    /**
     * Record an external proof of the kind given on the session, through
     * `conn-a`, with its evidence accepted as multifactor.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \Carbon\CarbonImmutable  $at
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @return void
     *
     * @throws \Throwable
     */
    private static function recordExternal(Session $session, ProofKind $kind, CarbonImmutable $at, ExternalEvidence $evidence): void
    {
        $purpose = $kind === ProofKind::FIRST_FACTOR ? Purpose::SIGN_IN : Purpose::REAUTHENTICATE;

        ProofWriter::record($session, (string) $session->getGuard(), new NewProof(
            $kind,
            $purpose,
            'sso',
            new Channel(ChannelKind::EXTERNAL_PROVIDER, 'conn-a'),
            null,
            new ObservedProperties,
            new Evaluation(true, true),
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $at,
            $evidence,
        ));
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
