<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget and timing contracts for a session's proofs: what a step-up and
 * a reauthentication cost, what asking the freshness policy and the
 * factor-change gate costs (nothing for an operation with no requirement), and
 * that the claims and freshness reads stay one query each, and quick, however
 * many proofs a session holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionStepUp::class)]
#[CoversClass(SessionReauthentication::class)]
#[CoversClass(ProofIssuance::class)]
#[CoversClass(ConfiguredFreshness::class)]
#[CoversClass(SessionProofs::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(FactorChangeGate::class)]
final class ProofQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithProofs, InteractsWithSessions;

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
