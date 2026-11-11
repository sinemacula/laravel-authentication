<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Feature tests of the policy-change helper's edges through the session
 * service, against a real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyChanges::class)]
#[CoversClass(SessionService::class)]
final class TenantPolicyChangesTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions, MarksSharedLocks;

    /** @var string A second connection to the test database, which a tenant may live on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy tenants answer with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /**
     * Freeze the clocks, create the tables, and bind the scripted policy and
     * the proof-judging check.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();

        $this->policy = new ScriptedTenantAuthenticationPolicy;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A tenant whose identifier names no tenant has no sessions to judge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantWithoutAnIdentifierChangesNothing(): void
    {
        $this->seedMember();
        $this->signedIn();

        $sessions = $this->sessions('members');
        $queries  = $this->countQueries();

        $this->policy->asked = [];

        self::assertSame(0, $sessions->tenantPolicyChanged(new ActivatableTenant));
        self::assertCount(0, $queries);
        self::assertSame([], $this->policy->asked);
        self::assertNull(Session::query()->sole()->getRevokedAt());
    }

    /**
     * The tables a session's principal and owning identity are read from.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideActorTables(): iterable
    {
        yield 'the principal' => ['activatable_tenant_memberships'];
        yield 'the owner' => ['activatable_tenant_members'];
    }

    /**
     * A session whose owner or principal no longer loads is judged short
     * without asking the policy.
     *
     * @param  string  $table
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideActorTables')]
    public function testASessionWhoseActorsNoLongerLoadIsJudgedShort(string $table): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $active  = $this->signedIn();
        $pending = $this->pendingFor();

        DB::table($table)->delete();

        $this->policy->requirement = new TenantRequirement('v1');
        $this->policy->asked       = [];

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($active->record->getKey())->getRevokedReason());
        self::assertNull($this->rowOf($pending)->getRevokedAt());
        self::assertSame([], $this->policy->asked);
        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($member->getKey()), $revoked->context->identityId);
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $revoked->context->principalId);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $revoked->context->tenantId);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, Session::query()->whereKey($revoked->context->sessionId)->sole()->getRevokedReason());
    }

    /**
     * A met session at the version the policy answers is judged but not
     * written, even when that version is `null`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMetSessionAtTheVersionAnsweredIsNotWritten(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $sessions = $this->sessions('members');
        $updates  = $this->countQueries('update');
        $asked    = count($this->policy->asked);

        self::assertSame(0, $sessions->tenantPolicyChanged($tenant));
        self::assertCount(0, $updates);
        self::assertCount($asked + 1, $this->policy->asked);
        self::assertNull($this->rowOf($session->record->getKey())->getTenantPolicyVersion());
        self::assertNull($this->rowOf($session->record->getKey())->getRevokedAt());
    }

    /**
     * Each session is judged with the connection it was established through,
     * read under the lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachSessionIsJudgedWithTheConnectionItWasEstablishedThrough(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $password = $this->signedIn()->record->getKey();
        $external = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a'), self::asPrincipal($membership))->session?->record->getKey();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);

        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));
        app()->instance(AdditionalFactorPolicy::class, $factors);

        $pending = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-b', 'link-2'), self::asPrincipal($membership))->pending?->id;

        self::assertNotNull($external);
        self::assertNotNull($pending);

        $asked = [];

        $this->policy->answer = static function (TenantPolicyContext $context) use (&$asked): TenantRequirement {
            $asked[IdentifierCoercion::stringify($context->session?->getSessionIdentifier()) ?? ''] = $context->connectionId();

            return new TenantRequirement('v2');
        };

        $this->sessions('members')->tenantPolicyChanged($tenant);

        self::assertEqualsCanonicalizing(
            [IdentifierCoercion::stringify($password) => null, IdentifierCoercion::stringify($external) => 'conn-a', IdentifierCoercion::stringify($pending) => 'conn-b'],
            $asked,
        );
    }

    /**
     * A session already recorded at the version the policy answers is not
     * judged again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRecordedAtTheVersionAnsweredIsNotJudgedAgain(): void
    {
        [, , $tenant] = $this->seedMember();

        $recorded = $this->signedIn()->record->getKey();
        $other    = $this->signedIn()->record->getKey();
        $none     = $this->signedIn()->record->getKey();

        Session::query()->whereKey($recorded)->update(['tenant_policy_version' => 'v1']);
        Session::query()->whereKey($other)->update(['tenant_policy_version' => 'v0']);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        self::assertSame(2, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertNull($this->rowOf($recorded)->getRevokedAt());
        self::assertNotNull($this->rowOf($other)->getRevokedAt());
        self::assertNotNull($this->rowOf($none)->getRevokedAt());
    }

    /**
     * A context the policy keeps cannot read the session's connection after the
     * re-judgement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeptContextCannotReadTheConnectionAfterTheReJudgement(): void
    {
        [, , $tenant] = $this->seedMember();

        $this->signedIn();

        $kept = [];

        $this->policy->answer = static function (TenantPolicyContext $context) use (&$kept): TenantRequirement {
            $kept[] = $context;

            return new TenantRequirement('v2');
        };

        $this->sessions('members')->tenantPolicyChanged($tenant);

        self::assertCount(1, $kept);

        $this->expectException(\LogicException::class);

        $kept[0]->connectionId();
    }

    /**
     * A session revoked between the helper's read and its write is neither
     * revoked again nor counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedMeanwhileIsNeitherRevokedAgainNorCounted(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $key     = $session->record->getKey();

        $this->policy->answer = static function () use ($key): TenantRequirement {

            DB::table('authentication_sessions')->where('id', $key)->update(['revoked_at' => Carbon::now(), 'revoked_reason' => RevocationReason::REVOKED->value]);

            return new TenantRequirement('v1', connections: ['conn-a']);
        };

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertSame(RevocationReason::REVOKED->value, $this->rowOf($key)->getRevokedReason());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A session that left the tenant between the helper's read and its write
     * keeps its version.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatLeftTheTenantMeanwhileKeepsItsVersion(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $key     = $session->record->getKey();

        $this->policy->answer = static function () use ($key): TenantRequirement {

            DB::table('authentication_sessions')->where('id', $key)->update(['tenant_id' => 'elsewhere']);

            return new TenantRequirement('v2');
        };

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));

        $row = $this->rowOf($key);

        self::assertNull($row->getTenantPolicyVersion());
        self::assertSame('elsewhere', $row->getTenantId());
        self::assertNull($row->getRevokedAt());
    }

    /**
     * Every session row is locked before any proof is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverySessionIsLockedBeforeAnyProofIsRead(): void
    {
        [, , $tenant] = $this->seedMember();

        $judged  = [$this->signedIn(), $this->signedIn()];
        $entered = $this->signedIn()->record->getKey();

        DB::table('authentication_sessions')->where('id', $entered)->update(['tenant_id' => 'elsewhere']);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        self::markSharedLocks();

        $entering = true;

        DB::listen(static function (QueryExecuted $query) use ($entered, $tenant, &$entering): void {
            if (!$entering || preg_match('/^select [`"]id[`"] from [`"]authentication_sessions[`"]/i', $query->sql) !== 1) {
                return;
            }

            $entering = false;

            DB::table('authentication_sessions')->where('id', $entered)->update(['tenant_id' => IdentifierCoercion::stringify($tenant->getKey())]);
        });

        $statements = self::statementsDuring(fn (): int => $this->sessions('members')->tenantPolicyChanged($tenant));

        $rows   = array_keys(array_filter($statements, static fn (string $sql): bool => preg_match('/^select .* from [`"]authentication_sessions[`"]/', $sql) === 1));
        $proofs = array_keys(array_filter($statements, self::readsProofs(...)));

        self::assertCount(2, $rows);
        self::assertSame([true, true], array_map(static fn (int $read): bool => self::locksForUpdate($statements[$read]), $rows));
        self::assertLessThan($proofs[0], $rows[1]);
        self::assertSame(array_fill(0, 4, self::takesSharedLocks()), array_map(static fn (int $read): bool => self::sharesLock($statements[$read]), $proofs));
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($judged[0]->record->getKey())->getRevokedReason());
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($judged[1]->record->getKey())->getRevokedReason());
        self::assertNull($this->rowOf($entered)->getRevokedAt());
        self::assertNull($this->rowOf($entered)->getTenantPolicyVersion());
    }

    /**
     * A session whose idle or absolute deadline has come is left alone for
     * pruning.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionsThatHaveEndedAreLeftAlone(): void
    {
        [, , $tenant] = $this->seedMember();

        $live     = $this->signedIn();
        $idleNow  = $this->signedIn();
        $idlePast = $this->signedIn();
        $absolute = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $idleNow->record->getKey())->update(['idle_expires_at' => $this->now]);
        DB::table('authentication_sessions')->where('id', $idlePast->record->getKey())->update(['idle_expires_at' => $this->now->subMinute()]);
        DB::table('authentication_sessions')->where('id', $absolute->record->getKey())->update(['absolute_expires_at' => $this->now]);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);
        $this->policy->asked       = [];

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertNotNull($this->rowOf($live->record->getKey())->getRevokedAt());

        foreach ([$idleNow, $idlePast, $absolute] as $ended) {
            self::assertNull($this->rowOf($ended->record->getKey())->getRevokedAt());
        }

        self::assertCount(1, $this->policy->asked);
        self::assertCount(1, $this->recordedClasses());
    }

    /**
     * A session with no absolute deadline is live until its idle one, so it is
     * judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutAnAbsoluteDeadlineIsJudged(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $session->record->getKey())->update(['absolute_expires_at' => null]);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertNotNull($this->rowOf($session->record->getKey())->getRevokedAt());
    }

    /**
     * A session that records no guard is judged for the empty application name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatRecordsNoGuardIsJudgedForNone(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $session->record->getKey())->update(['guard' => null]);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);
        $this->policy->asked       = [];

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertSame('', $this->policy->asked[0]->application ?? null);
        self::assertNull($this->recordedEvent(SessionRevoked::class)->context->guard);
        self::assertNotNull($this->rowOf($session->record->getKey())->getRevokedAt());
    }

    /**
     * The second pass waits for a transaction on the storage connection alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassWaitsForTheStorageConnection(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn()->record->getKey();
        $changed = clone $tenant;

        $changed->setConnection(self::ELSEWHERE);

        DB::transaction(function () use ($changed, $session): void {

            self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($changed));

            $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

            self::assertNull($this->rowOf($session)->getRevokedAt());
        });

        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($session)->getRevokedReason());
    }

    /**
     * A plain tenant's second pass waits for the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassWaitsForTheStorageConnectionForAPlainTenant(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn()->record->getKey();
        $plain   = new PlainTenantFixture(IdentifierCoercion::stringify($tenant->getKey()) ?? '');

        DB::transaction(function () use ($plain, $session): void {

            self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($plain));

            $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

            self::assertNull($this->rowOf($session)->getRevokedAt());
        });

        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($session)->getRevokedReason());
    }

    /**
     * The second pass waits for a transaction on the tenant's connection alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassWaitsForTheTenantsConnection(): void
    {
        [, , $tenant] = $this->seedMember();

        $session   = $this->signedIn()->record->getKey();
        $changed   = clone $tenant;
        $elsewhere = DB::connection(self::ELSEWHERE);

        $changed->setConnection(self::ELSEWHERE);
        $elsewhere->beginTransaction();

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($changed));

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        self::assertNull($this->rowOf($session)->getRevokedAt());

        $elsewhere->commit();

        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($session)->getRevokedReason());
    }

    /**
     * The second pass still runs when the request ends after a commit callback
     * of the application's, registered first, threw.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassRunsAtTheEndOfTheRequestWhenAnEarlierCommitCallbackThrew(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn()->record->getKey();

        DB::beginTransaction();
        DB::afterCommit(static fn () => throw new \RuntimeException('application'));

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        try {
            DB::commit();
        } catch (\RuntimeException $exception) {
            self::assertSame('application', $exception->getMessage());
        }

        self::assertNull($this->rowOf($session)->getRevokedAt());

        app()->terminate();

        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($session)->getRevokedReason());
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('database.connections.' . self::ELSEWHERE, $config->get('database.connections.' . $config->string('database.default')));
    }

    /**
     * Sign the seeded member in with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * A pending session of the seeded member waiting on a further factor its
     * tenant asked for, and its key.
     *
     * @return mixed
     *
     * @throws \Throwable
     */
    private function pendingFor(): mixed
    {
        $requirement = $this->policy->requirement;

        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart));

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertTrue($result->isPending());

        $this->policy->requirement = $requirement;

        return $result->pending?->id;
    }

    /**
     * The stored row of the session with the key given.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function rowOf(mixed $key): Session
    {
        return Session::query()->whereKey($key)->firstOrFail();
    }

    /**
     * Count the statements run from now on, those starting with the verb given
     * when there is one.
     *
     * @param  ?string  $verb
     * @return \ArrayObject<int, string>
     */
    private function countQueries(?string $verb = null): \ArrayObject
    {
        $queries = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($queries, $verb): void {

            if ($verb !== null && !str_starts_with(strtolower($query->sql), $verb)) {
                return;
            }

            $queries->append($query->sql);
        });

        return $queries;
    }
}
