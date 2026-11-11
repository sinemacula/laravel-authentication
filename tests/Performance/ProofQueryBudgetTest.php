<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session as Contract;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;

/**
 * Query-budget and timing contracts for a session's proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionStepUp::class)]
#[CoversClass(SessionReauthentication::class)]
#[CoversClass(ExternalReauthentication::class)]
#[CoversClass(ProofIssuance::class)]
#[CoversClass(ConfiguredFreshness::class)]
#[CoversClass(SessionProofs::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(FactorChangeGate::class)]
#[CoversClass(RequirementJudge::class)]
#[CoversClass(ActiveSessionProofs::class)]
#[CoversClass(ContributionSubject::class)]
final class ProofQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var int Proofs a long-lived session holds in the bounded-read contracts. */
    private const int MANY = 200;

    /** @var float Most seconds one claims or freshness read may take over a session with many proofs. */
    private const float READ_CEILING_SECONDS = 0.25;

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
     * A step-up reads three times and writes its issuance guard and the proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpReadsThriceAndWritesItsGuardAndTheProof(): void
    {
        $session  = $this->signedIn();
        $sessions = $this->sessions();
        $proof    = self::adapterProof($session->identity, 'api', $session->record->getKey());

        self::assertTrue($this->assertQueryBudget(3, 2, static fn (): AccessTokenResult => $sessions->stepUp($proof, self::requestClient()))->isIssued());
    }

    /**
     * A reauthentication has a fixed budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationHasAFixedBudget(): void
    {
        $session  = $this->signedIn();
        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(
            5,
            8,
            static fn (): AccessTokenResult => $sessions->reauthenticate($session->record, 'password', self::credentials(), self::requestClient()),
        )->isIssued());
    }

    /**
     * An external reauthentication and a locked standing each have a fixed
     * budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalReauthenticationAndAStandingHaveFixedBudgets(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();
        $session  = $sessions->signInExternally($this->linkedResult($identity, subject: 'subject-1'), self::requestContext())->session;
        $result   = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: CarbonImmutable::now());

        self::assertNotNull($session);
        self::assertTrue(
            $this->assertQueryBudget(
                5,
                2,
                static fn (): AccessTokenResult => $sessions->reauthenticateExternally($session->record->getKey(), $result, self::requestClient()),
            )->isIssued(),
        );

        $standing = $this->assertQueryBudget(2, 0, static fn (): ?FailureReason => DB::transaction(
            static fn (): ?FailureReason => $sessions->externalStanding($session->record->getKey(), $session->identity, 'connection-7', 'link-1'),
        ));

        self::assertNull($standing);
    }

    /**
     * A principal's external reauthentication and an unlocked standing each
     * have a fixed budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsExternalReauthenticationAndAnUnlockedStandingHaveFixedBudgets(): void
    {
        [$member, $membership] = $this->seedMember();

        $policy   = new ScriptedTenantAuthenticationPolicy;
        $sessions = $this->sessions('members');
        $now      = CarbonImmutable::now();
        $evidence = new ExternalEvidence(['mfa'], null, $now);

        app()->instance(TenantAuthenticationPolicy::class, $policy);
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $session = $sessions->signInExternally($this->linkedResult($member, subject: 'subject-1', evidence: $evidence), self::asPrincipal($membership))->session;
        $result  = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $now);

        self::assertNotNull($session);

        $key = $session->record->getKey();

        self::assertTrue($this->assertQueryBudget(7, 2, static fn (): AccessTokenResult => $sessions->reauthenticateExternally($key, $result, self::requestClient()))->isIssued());

        $policy->requirement = new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart), ['connection-7']);

        self::assertTrue($this->assertQueryBudget(10, 2, static fn (): AccessTokenResult => $sessions->reauthenticateExternally($key, $result, self::requestClient()))->isIssued());
        self::assertNull($this->assertQueryBudget(2, 0, static fn (): ?FailureReason => $sessions->externalStanding($key, $member, 'connection-7')));
    }

    /**
     * Asking the freshness policy reads the session and its freshest proof, or
     * nothing without a requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingTheFreshnessPolicyReadsTwiceOrNotAtAll(): void
    {
        $record = $this->signedIn()->record;
        $policy = app(FreshnessPolicy::class);
        $plain  = \Mockery::mock(Contract::class);

        $plain->shouldReceive('getGuard')->andReturn('api');
        $plain->shouldReceive('getSessionIdentifier')->andReturn($record->getKey());

        $current = static fn (Contract $session, string $operation): ?RecordedProof => DB::transaction(
            static fn (): ?RecordedProof => $policy->freshProof($session, $operation, current: true),
        );

        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => $policy->freshProof($record, Operations::IDENTIFIER_CHANGE)));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?CarbonImmutable => $policy->freshUntil($record, Operations::IDENTIFIER_CHANGE, null, 'factor-a')));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => $current($record, Operations::IDENTIFIER_CHANGE)));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?CarbonImmutable => DB::transaction(
            static fn (): ?CarbonImmutable => $policy->freshUntil($record, Operations::IDENTIFIER_CHANGE, current: true),
        )));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $policy->freshProof($record, 'mfa.add_factor')));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?CarbonImmutable => $policy->freshUntil($record, 'mfa.add_factor')));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $current($record, 'mfa.add_factor')));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $policy->freshProof($plain, Operations::IDENTIFIER_CHANGE)));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $current($plain, Operations::IDENTIFIER_CHANGE)));
    }

    /**
     * The factor-change gate locks the session and reads it and its freshest
     * proof, however many proofs it holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorChangeGateLocksAndReadsTwice(): void
    {
        $signedIn = $this->signedIn();
        $record   = $signedIn->record;

        foreach (range(1, self::MANY) as $index) {
            self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->copy()->subSeconds($index), ['otp'], new Evaluation(true, true));
        }

        $sessions = $this->sessions();

        $removal = $this->assertQueryBudget(3, 0, static fn (): FactorChangeVerdict => $sessions->factorChange($record, FactorChange::REMOVE, factor: 'factor-a'));

        self::assertTrue($removal->isAllowed());
        self::assertFalse($this->assertQueryBudget(3, 0, static fn (): FactorChangeVerdict => $sessions->factorChange($record, FactorChange::ADD_FIRST))->isAllowed());
    }

    /**
     * The claims and freshness reads are one query each over many proofs, and
     * quick.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReadsAreBoundedHoweverManyProofsASessionHolds(): void
    {
        $record = $this->signedIn()->record;

        foreach (range(1, self::MANY) as $index) {
            self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->copy()->addSeconds($index), ['otp'], new Evaluation(true, $index % 2 === 0));
        }

        $started = hrtime(true);
        $summary = $this->assertQueryBudget(1, 0, static fn (): AuthenticationSummary => AuthenticationClaims::forSession($record));
        $claims  = (hrtime(true) - $started) / 1e9;

        $now         = $this->now->toImmutable()->addSeconds(self::MANY);
        $requirement = new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]);

        $started = hrtime(true);
        $newest  = $this->assertQueryBudget(1, 0, static fn (): ?RecordedProof => SessionProofs::newestMeeting($record, $requirement, $now));
        $fresh   = (hrtime(true) - $started) / 1e9;

        self::assertSame(['pwd', 'otp', 'mfa'], $summary->methods);
        self::assertSame($now->getTimestamp(), $newest?->authenticatedAt->getTimestamp());
        self::assertLessThan(self::READ_CEILING_SECONDS, $claims);
        self::assertLessThan(self::READ_CEILING_SECONDS, $fresh);
    }

    /**
     * The newest accepted evidence is one quick query however many external
     * proofs a session holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAcceptedEvidenceReadIsBoundedHoweverManyProofsASessionHolds(): void
    {
        $record   = $this->signedIn()->record;
        $identity = $record->authenticatable()->first();

        self::assertInstanceOf(Identity::class, $identity);

        DB::table('authentication_proofs')->delete();

        foreach (range(0, self::MANY) as $index) {
            $at = $this->now->toImmutable()->addSeconds($index);

            ProofWriter::record($record, 'api', new NewProof(
                $index === 0 ? ProofKind::FIRST_FACTOR : ProofKind::EXTERNAL_REAUTHENTICATION,
                $index === 0 ? Purpose::SIGN_IN : Purpose::REAUTHENTICATE,
                'sso',
                new Channel(ChannelKind::EXTERNAL_PROVIDER, 'conn-a'),
                null,
                new ObservedProperties,
                new Evaluation(true, true),
                [FirstFactor::EXTERNAL_PROVIDER_METHOD],
                $at,
                new ExternalEvidence(['hwk'], null, $at),
            ));
        }

        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $now     = $this->now->toImmutable()->addSeconds(self::MANY);
        $started = hrtime(true);
        $held    = $this->assertQueryBudget(1, 0, static fn (): array => SessionProofs::acceptedEvidence($record));
        $read    = (hrtime(true) - $started) / 1e9;

        self::assertCount(1, $held);
        self::assertSame($now->getTimestamp(), $held[0]->authenticatedAt->getTimestamp());
        self::assertLessThan(self::READ_CEILING_SECONDS, $read);
        $requirement = new Requirement(multifactor: new RequirementPart);

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => RequirementJudge::isMet('api', $identity, $record, null, $now, new ProofSource, $requirement)));
    }

    /**
     * The session service's proof reads cost the session and one bounded page
     * of its proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheServicesProofReadsHaveFixedBudgets(): void
    {
        $record   = $this->signedIn()->record;
        $key      = $record->getKey();
        $sessions = $this->sessions();

        foreach (range(1, self::MANY) as $index) {
            self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->copy()->addSeconds($index), ['otp'], new Evaluation(true, true));
        }

        $started = hrtime(true);
        $proofs  = $this->assertQueryBudget(2, 0, static fn (): array => $sessions->proofs($key, limit: self::MANY));
        $read    = (hrtime(true) - $started) / 1e9;

        self::assertCount(self::MANY, $proofs);
        self::assertLessThan(self::READ_CEILING_SECONDS, $read);
        self::assertCount(self::MANY, $this->assertQueryBudget(2, 0, static fn (): array => DB::transaction(static fn (): array => $sessions->proofs($key, limit: self::MANY))));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => $sessions->firstFactor($key)));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => DB::transaction(static fn (): ?RecordedProof => $sessions->firstFactor($key))));
        self::assertSame([], $this->assertQueryBudget(0, 0, static fn (): array => $sessions->proofs('not-a-key')));
        self::assertNull($this->assertQueryBudget(1, 0, static fn (): ?RecordedProof => $sessions->firstFactor((string) Str::uuid7())));

        DB::table('authentication_sessions')->where('id', $key)->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        self::assertSame([], $this->assertQueryBudget(1, 0, static fn (): array => DB::transaction(static fn (): array => $sessions->proofs($key))));
        self::assertNull($this->assertQueryBudget(1, 0, static fn (): ?RecordedProof => $sessions->firstFactor($key)));
    }

    /**
     * A contribution subject's proof reads query on every call, and nothing
     * without a session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectsProofReadsReadOnEveryCall(): void
    {
        $signedIn = $this->signedIn();
        $identity = $signedIn->identity;
        $id       = IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $context  = new AuthenticationContext(
            SubjectType::PERSON,
            'identity',
            $id,
            'identity',
            $id,
            null,
            null,
            'api',
            null,
            [],
            null,
            false,
            false,
            false,
            null,
            null,
            null,
            null,
        );
        $subject = new ContributionSubject($context, $identity, $signedIn->principal, null, $signedIn->record);
        $none    = new ContributionSubject($context, $identity, $signedIn->principal, null, null);

        for ($call = 1; $call <= 2; $call++) {
            self::assertCount(1, $this->assertQueryBudget(2, 0, static fn (): array => $subject->proofs()));
            self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => $subject->firstFactor()));
        }

        self::assertSame([], $this->assertQueryBudget(0, 0, static fn (): array => $none->proofs()));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $none->firstFactor()));
    }

    /**
     * Configure the session guards.
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
     * A session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }
}
