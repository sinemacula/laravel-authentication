<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Integration tests that a pending session is read on the primary while the
 * replica lags.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessions::class)]
#[CoversClass(PendingEvaluation::class)]
#[CoversClass(SessionActivation::class)]
final class ReplicaPendingSessionsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose sign-ins wait for a choice of principal. */
    private const string CHOOSERS = 'choosers';

    /** @var bool Whether the bound factor policy asks for a further factor. */
    private bool $factorRequired = true;

    /**
     * Freeze the clocks, create the identity and tenant tables on both
     * connections, and bind a switchable factor policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createOnPrimaryAndReplica('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($this) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \Tests\Integration\Sessions\ReplicaPendingSessionsTest  $test
             */
            public function __construct(

                /** The test whose switch the policy answers with. */
                private ReplicaPendingSessionsTest $test,
            ) {}

            /**
             * Answer with the test's switch.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $this->test->isFactorRequired() ? new Requirement(new RequirementPart) : new Requirement;
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Release the clocks and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * Whether the factor policy asks for a further factor now.
     *
     * @return bool
     */
    public function isFactorRequired(): bool
    {
        return $this->factorRequired;
    }

    /**
     * A pending session only the primary holds is found and satisfied there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionIsFoundAndSatisfiedOnThePrimary(): void
    {
        $identity = $this->seedIdentity();

        $result = $this->pendingSignIn('api', 'ada@example.test');

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());

        $found = $this->sessions()->pending((string) $result->credential?->reveal(), PendingAction::VERIFY);

        self::assertNotNull($found);
        self::assertIsModel($identity, $found->principal);

        $satisfied = $this->sessions()->satisfy(
            (string) $result->credential?->reveal(),
            self::adapterProof($identity, 'api', $result->pending?->id, Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($satisfied->isSignedIn());
        self::assertSame('active', DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->value('status'));
        self::assertSame(2, DB::connection(self::PRIMARY_CONNECTION)->table('authentication_proofs')->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->count());
    }

    /**
     * A choice lists and records principals only the primary holds, and
     * activates the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsListedAndMadeOnThePrimary(): void
    {
        $this->factorRequired = false;

        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('activatable_tenant_memberships')->count());

        $result = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $listed = $this->sessions(self::CHOOSERS)->pending((string) $result->credential?->reveal(), PendingAction::LIST_PRINCIPALS);

        self::assertNotNull($listed);
        self::assertCount(2, $listed->principals);

        $chosen = $this->sessions(self::CHOOSERS)->choose((string) $result->credential?->reveal(), $memberships[1], self::requestClient());

        self::assertTrue($chosen->isSignedIn());

        $row = DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->sole();

        self::assertSame(IdentifierCoercion::stringify($memberships[1]->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($memberships[1]->tenant_id), $row->tenant_id);
    }

    /**
     * Configure the session guards, the choosers' guard and the lagging
     * read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Sign the identity in on the guard, expecting a pending session with a
     * credential.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function pendingSignIn(string $guard, string $email): SignInResult
    {
        $result = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        return $result;
    }
}
