<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;

/**
 * Query-budget contracts for the factor package's mandatory triggers: a
 * factor's removal costs the bulk revocation of the identity's other sessions,
 * then one locking read of the current session, one `UPDATE` writing its
 * issuance guard (so an issuance of the session that overlaps the removal never
 * counts the factor's proofs), one `UPDATE` voiding its proofs with the factor,
 * and the reads of judging it again as a refresh does (its
 * owner and its first factor, and the requirement's page of proofs while a
 * further factor is asked), plus the return to pending's one `UPDATE` when it
 * falls short; without a current session, it is the bulk revocation alone, and
 * so is a reset. An addition, a change of the factor package's that removes
 * no factor, judges the current session alone: the locking read, the issuance
 * guard's `UPDATE` and the same reads of judging it again, plus the return's
 * `UPDATE` when it falls short; a current session that is no longer live costs
 * the locking read alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRevocations::class)]
final class FactorRevocationsQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

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
     * A removal that keeps the current session active revokes the two other
     * sessions in bulk, locks the current one, writes its issuance guard, voids
     * its proofs with the factor and judges it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalKeepingTheCurrentSessionCostsItsRecheck(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $current  = $this->signIn();
        $sessions = $this->sessions();

        $removal = $this->assertQueryBudget(4, 4, static fn (): FactorRemoval => $sessions->factorRemoved($identity, 'factor-a', $current->record));

        self::assertSame(2, $removal->revoked);
        self::assertFalse($removal->isPending());
    }

    /**
     * A removal that returns the current session to pending costs the same, the
     * requirement's page of proofs and the one `UPDATE` of the return.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalReturningTheCurrentSessionToPendingCostsOneUpdateMore(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $identity = $this->seedIdentity();

        $this->satisfied();
        $this->satisfied();

        $current  = $this->satisfied();
        $sessions = $this->sessions();

        $removal = $this->assertQueryBudget(5, 5, static fn (): FactorRemoval => $sessions->factorRemoved($identity, 'factor-a', $current->record));

        self::assertSame(2, $removal->revoked);
        self::assertTrue($removal->isPending());
    }

    /**
     * Without a current session, a removal is the bulk revocation alone: one
     * chunk read and an `UPDATE` per session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalWithoutACurrentSessionCostsABulkRevocation(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $sessions = $this->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 2, static fn (): int => $sessions->factorRemoved($identity, 'factor-a')->revoked));
    }

    /**
     * A reset is the bulk revocation of every session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetCostsABulkRevocation(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $sessions = $this->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 2, static fn (): int => $sessions->factorReset($identity)));
    }

    /**
     * A change that keeps the current session active locks it, writes its
     * issuance guard and judges it again as a refresh does (its owner, its
     * first factor and the requirement's page of proofs): four reads and one
     * `UPDATE`, no other session read or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeKeepingTheCurrentSessionActiveCostsItsJudgement(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $identity = $this->seedIdentity();

        $this->satisfied();

        $current  = $this->satisfied();
        $sessions = $this->sessions();

        $change = static fn (): FactorChangeResult => $sessions->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($this->assertQueryBudget(4, 1, $change)->isActive());
    }

    /**
     * A change that returns the current session to pending costs the same and
     * the one `UPDATE` of the return; the identity's other session is not read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeReturningTheCurrentSessionToPendingCostsOneUpdateMore(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        $current  = $this->signIn();
        $sessions = $this->sessions();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $change = static fn (): FactorChangeResult => $sessions->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($this->assertQueryBudget(4, 2, $change)->isPending());
    }

    /**
     * A change whose current session is no longer live is the locking read
     * alone, and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeSkippingTheCurrentSessionCostsTheLockAlone(): void
    {
        $identity = $this->seedIdentity();
        $current  = $this->signIn();
        $sessions = $this->sessions();

        $sessions->revokeSession($identity, $current->record->getKey(), RevocationReason::REVOKED);

        $change = static fn (): FactorChangeResult => $sessions->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($this->assertQueryBudget(1, 0, $change)->isSkipped());
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
     * A session of the seeded identity, signed in with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A session of the seeded identity that signed in pending a further factor
     * and was activated with `factor-a`.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function satisfied(): SignedInSession
    {
        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-a',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($pending->pending->identity, 'api', $pending->pending->id, Purpose::SIGN_IN),
        );

        $session = $this->sessions()->satisfy($pending->credential, $proof, self::requestClient())->session;

        self::assertNotNull($session);

        return $session;
    }
}
