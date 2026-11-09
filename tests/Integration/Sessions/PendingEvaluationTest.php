<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Fixtures\Proofs\UndescribedSignInProof;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for asking the additional-factor policy on the write
 * connection, against a read/write split whose replica lags behind its primary:
 * the identity's (`landlord`).
 *
 * The policy asks for a further factor only when its query-builder read on that
 * connection finds a row written through the split connection, which exists on
 * the primary only: a requirement shows the read was served by the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingEvaluation::class)]
final class PendingEvaluationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Table of the factors the policy reads. */
    private const string FACTORS = 'factors';

    /**
     * Create the factors table on the landlord primary and replica, and bind a
     * policy that asks for a factor only when the identity's connection finds
     * one.
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

        $this->app?->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor when the identity's connection finds one
             * enrolled.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return DB::connection('landlord')->table('factors')->exists() ? new Requirement(new RequirementPart) : new Requirement;
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
     * A factor enrolled on the primary only is found, so the policy asks for
     * it, and the identity's connection reads from its replica again
     * afterwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePolicyIsAskedOnTheIdentitysWriter(): void
    {
        DB::connection(self::LANDLORD_CONNECTION)->table(self::FACTORS)->insert(['id' => 1]);

        self::assertFalse($this->factorRequirement()->isEmpty());
        self::assertFalse(DB::connection(self::LANDLORD_CONNECTION)->table(self::FACTORS)->exists());
    }

    /**
     * With no factor on the primary either, the policy asks for nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAFactorNothingIsAsked(): void
    {
        self::assertTrue($this->factorRequirement()->isEmpty());
    }

    /**
     * Use a lagging landlord split beside the default connection, and a guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $this->configureLaggingLandlordReplica($config);

        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubPrincipal::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
    }

    /**
     * Create no package tables: the tests read only their own.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * Ask the policy about an identity stored on the landlord connection.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Throwable
     */
    private function factorRequirement(): Requirement
    {
        $identity = new class extends StubPrincipal {
            /** @var string|\UnitEnum|null The connection the identity is stored on. */
            protected $connection = 'landlord';
        };

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $first = UndescribedSignInProof::of('password', CarbonImmutable::now())->recorded();

        return (new PendingEvaluation($guard->context(), app()))->factorRequirement($identity, $first, new ClientContext(null, null), null, null, null);
    }
}
