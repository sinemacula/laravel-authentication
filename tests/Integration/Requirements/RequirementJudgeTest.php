<?php

declare(strict_types = 1);

namespace Tests\Integration\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for asking the requirement check on the write connection,
 * against a read/write split whose replica lags behind its primary: the
 * identity's (`landlord`).
 *
 * The check finds the requirement met only when its query-builder read on that
 * connection finds a row written through the split connection, which exists on
 * the primary only: a met requirement shows the read was served by the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementJudge::class)]
final class RequirementJudgeTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Table of the factors the check reads. */
    private const string FACTORS = 'factors';

    /**
     * Create the factors table on the landlord primary and replica, and bind a
     * check that finds a factor only on the identity's connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica(self::FACTORS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        $this->app?->instance(RequirementCheck::class, new class implements RequirementCheck {
            /**
             * Meet the requirement when the identity's connection finds a
             * factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
             * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
             * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
             */
            #[\Override]
            public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
            {
                return new RequirementEvaluation(DB::connection('landlord')->table('factors')->exists() ? [] : $requirement->kinds());
            }
        });
    }

    /**
     * Remove the temporary primary and replica files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A factor recorded on the primary only is found, so the requirement is
     * met, and the identity's connection reads from its replica again
     * afterwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRequirementCheckIsAskedOnTheIdentitysWriter(): void
    {
        DB::connection(self::LANDLORD_CONNECTION)->table(self::FACTORS)->insert(['id' => 1]);

        self::assertTrue($this->isFurtherFactorMet());
        self::assertFalse(DB::connection(self::LANDLORD_CONNECTION)->table(self::FACTORS)->exists());
    }

    /**
     * With no factor on the primary either, the requirement is not met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAFactorTheFurtherFactorIsRequired(): void
    {
        self::assertFalse($this->isFurtherFactorMet());
    }

    /**
     * Use a lagging landlord split beside the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingLandlordReplica(app(ConfigRepository::class));
    }

    /**
     * Create no package tables: the tests read only their own.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * Judge a sign-in's evidence, for an identity stored on the landlord
     * connection, against a requirement of a further factor.
     *
     * @return bool
     *
     * @throws \Throwable
     */
    private function isFurtherFactorMet(): bool
    {
        $identity = new class extends StubPrincipal {
            /** @var string|\UnitEnum|null The connection the identity is stored on. */
            protected $connection = 'landlord';
        };

        $now      = CarbonImmutable::now();
        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));

        return RequirementJudge::isMet('members', $identity, null, null, $now, new ProofSource($evidence), new Requirement(new RequirementPart));
    }
}
