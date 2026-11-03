<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\Operations;
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
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;

/**
 * Query-budget and timing contracts for a session's proofs: what a step-up and
 * a reauthentication cost, what asking the freshness policy and the
 * factor-change gate costs (nothing for an operation with no requirement), and
 * that the claims, freshness and accepted-evidence reads stay one query each,
 * and quick, however many proofs a session holds.
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
     * A step-up locks the session, reloads its owner, records the proof and
     * reads the session's proofs for the new access token: three reads and one
     * write, the refresh state untouched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpReadsThriceAndWritesTheProofOnly(): void
    {
        $session  = $this->signedIn();
        $sessions = $this->sessions();
        $proof    = self::adapterProof($session->identity, 'api', $session->record->getKey());

        self::assertTrue($this->assertQueryBudget(3, 1, static fn (): AccessTokenResult => $sessions->stepUp($proof))->isIssued());
    }

    /**
     * A reauthentication reads the session, then the identity the password
     * names, and, under the lock, the session and its owner again and the
     * proofs for the new token; it reserves and gives back a slot on each of
     * the three counters the sign-in created, and writes the proof.
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
            7,
            static fn (): AccessTokenResult => $sessions->reauthenticate($session->record, 'password', self::credentials()),
        )->isIssued());
    }

    /**
     * An external reauthentication reads the session, then, under the lock, the
     * session, its provenance, its owner and its proofs for the new token, and
     * writes the proof; the link contract, here a fake, reads nothing of the
     * package's. A locked standing reads the session and its provenance and
     * writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalReauthenticationAndAStandingHaveFixedBudgets(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();
        $session  = $sessions->signInExternally($this->linkedResult($identity, subject: 'subject-1'))->session;
        $result   = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: CarbonImmutable::now());

        self::assertNotNull($session);
        self::assertTrue($this->assertQueryBudget(5, 1, static fn (): AccessTokenResult => $sessions->reauthenticateExternally($session->record, $result))->isIssued());

        $standing = $this->assertQueryBudget(2, 0, static fn (): ?FailureReason => DB::transaction(
            static fn (): ?FailureReason => $sessions->externalStanding($session->record, $session->identity, 'connection-7', 'link-1'),
        ));

        self::assertNull($standing);
    }

    /**
     * Asking the freshness policy reads the session and its freshest proof;
     * an operation with no requirement reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingTheFreshnessPolicyReadsTwiceOrNotAtAll(): void
    {
        $record = $this->signedIn()->record;
        $policy = app(FreshnessPolicy::class);

        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?RecordedProof => $policy->freshProof($record, Operations::IDENTIFIER_CHANGE)));
        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?CarbonImmutable => $policy->freshUntil($record, Operations::IDENTIFIER_CHANGE, null, 'factor-a')));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?RecordedProof => $policy->freshProof($record, 'mfa.add_factor')));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?CarbonImmutable => $policy->freshUntil($record, 'mfa.add_factor')));
    }

    /**
     * Asking the factor-change gate locks the session's row, then reads it and
     * its freshest proof as the freshness policy does, and writes nothing,
     * however many proofs the session holds.
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
     * The claims and freshness reads are one query each over a session with
     * many step-ups, one a second after the sign-in, and each stays well within
     * its ceiling.
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
     * The newest accepted evidence is one query however many external proofs a
     * session holds, within its ceiling, and judging an external session's
     * requirement on it costs that one read beside its first factor's; the
     * requirement check is not asked once the evidence meets it.
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

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => RequirementJudge::isMet('api', $identity, $record, null, $now, null, $requirement)));
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

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }
}
