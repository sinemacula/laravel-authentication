<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Integration tests of the policy-change helper against real rows on each
 * supported database: chunked locking reads past one chunk, each session judged
 * once; the helper inside a caller's transaction on the storage connection,
 * committing or rolling back with it; and a refresh or a switch whose
 * compare-and-swap loses to the helper's write, judged again from the row it
 * left.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyChanges::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(SwitchesSessions::class)]
final class TenantPolicyChangesTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every change is applied at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy tenants answer with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /**
     * Freeze the clocks, the tokens' among them, create the tables and bind the
     * scripted policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        JWT::$timestamp = CarbonImmutable::parse(self::NOW)->getTimestamp();

        $this->createSessionTables();

        $this->policy = new ScriptedTenantAuthenticationPolicy;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);
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
     * More sessions than two chunks are each judged once: their keys are read
     * in three locking reads that page by key, and only then the sessions, in
     * three locking reads of those keys; every one records the version
     * answered, and a second call skips them all, writing nothing. The policy
     * counts what it is asked rather than keeping every context, so the test
     * holds no session it judged once the helper is done with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverySessionPastTwoChunksIsJudgedOnce(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $count = TenantPolicyChanges::CHUNK * 2 + 1;

        $this->insertSessions($member, $membership, $tenant, $count);

        $policy = self::countingPolicy(new TenantRequirement('v1'));

        $chunk = 'limit ' . TenantPolicyChanges::CHUNK;
        $reads = $this->countQueries(static fn (string $sql): bool => str_starts_with($sql, 'select') && str_contains($sql, 'from ' . self::quoted('authentication_sessions')));

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertCount(6, $reads);
        self::assertSame([true, true, true, false, false, false], array_map(static fn (string $sql): bool => str_contains($sql, $chunk), $reads->getArrayCopy()));
        self::assertSame([false, false, false, true, true, true], array_map(static fn (string $sql): bool => str_contains($sql, ' in ('), $reads->getArrayCopy()));
        self::assertSame($count, $policy->judged);
        self::assertSame($count, DB::table('authentication_sessions')->where('tenant_policy_version', 'v1')->count());

        $updates = $this->countQueries(static fn (string $sql): bool => str_starts_with($sql, 'update'));

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertCount(0, $updates);
    }

    /**
     * More sessions than two chunks that all fall short are all revoked, each
     * counted and reported once. Only the identifier of each session reported
     * is kept, so the test holds none of the sessions it revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverySessionPastTwoChunksThatFallsShortIsRevokedOnce(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $count = TenantPolicyChanges::CHUNK * 2 + 1;

        $this->insertSessions($member, $membership, $tenant, $count);

        $this->policy->requirement = new TenantRequirement('v1', connections: []);

        $reported = new \ArrayObject;

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use ($reported): void {
            $reported->append($event->context->sessionId);
        });

        self::assertSame($count, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame($count, DB::table('authentication_sessions')->where('revoked_reason', RevocationReason::TENANT_POLICY_CHANGED->value)->count());
        self::assertCount($count, $reported);
        self::assertCount($count, array_unique($reported->getArrayCopy()));
    }

    /**
     * Inside a caller's transaction on the storage connection, the helper's
     * work commits with the caller's, and is reported only once that commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHelperCommitsWithTheCallersTransaction(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->insertSessions($member, $membership, $tenant, 2);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        $this->recordEvents([SessionRevoked::class]);

        DB::transaction(function () use ($tenant): void {

            ActivatableTenant::query()->whereKey($tenant->getKey())->update(['name' => 'Published']);

            self::assertSame(2, $this->sessions('members')->tenantPolicyChanged($tenant));
            self::assertSame([], $this->recorded);
        });

        self::assertSame('Published', ActivatableTenant::query()->whereKey($tenant->getKey())->value('name'));
        self::assertSame(2, DB::table('authentication_sessions')->where('revoked_reason', RevocationReason::TENANT_POLICY_CHANGED->value)->count());
        self::assertCount(2, $this->recorded);
    }

    /**
     * Inside a caller's transaction on the storage connection that rolls back,
     * the helper's revocations roll back with the caller's own work, and none
     * is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHelperRollsBackWithTheCallersTransaction(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->insertSessions($member, $membership, $tenant, 2);

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        $this->recordEvents([SessionRevoked::class]);

        DB::beginTransaction();

        ActivatableTenant::query()->whereKey($tenant->getKey())->update(['name' => 'Published']);

        self::assertSame(2, $this->sessions('members')->tenantPolicyChanged($tenant));

        DB::rollBack();

        self::assertSame('Tenant', ActivatableTenant::query()->whereKey($tenant->getKey())->value('name'));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->recorded);
    }

    /**
     * A refresh that loses its rotation to a policy change revoking its session
     * fails as `session_revoked`, and the revocation stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshLosingToAPolicyChangeThatRevokesItFails(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->beforeTheUpdate('previous_refresh_key', function () use ($tenant): void {

            $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

            self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        });

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh($session->tokens->refreshToken?->reveal());

        self::assertSame(FailureReason::SESSION_REVOKED, $refused->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A refresh that loses its rotation to a policy change recording a new
     * version on its session is a conflict the client can retry: the version
     * stands, the token is still the current one, and nothing is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshLosingToARecordedVersionIsAConflict(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();
        $digest  = DB::table('authentication_sessions')->value('refresh_key');

        $this->beforeTheUpdate('previous_refresh_key', function () use ($tenant): void {

            $this->policy->requirement = new TenantRequirement('v9');

            self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
        });

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh($session->tokens->refreshToken?->reveal());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(FailureReason::ROTATION_CONFLICT, $refused->reason);
        self::assertSame('v9', $row->tenant_policy_version);
        self::assertSame($digest, $row->refresh_key);
        self::assertNull($row->revoked_at);
        self::assertTrue(self::sessionsOf($this->freshGuard('members'))->refresh($session->tokens->refreshToken?->reveal())->isRefreshed());
    }

    /**
     * A switch that loses its write to a policy change revoking its session in
     * the tenant it is leaving fails as `session_revoked`: the session is
     * revoked where it was, never moved to the other tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchLosingToAPolicyChangeThatRevokesItFails(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $other   = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $target  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $session = $this->signIn($first);

        $this->beforeTheUpdate('previous_refresh_key', function () use ($tenant): void {

            $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

            self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        });

        $refused = $this->sessions('members')->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($target));

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(FailureReason::SESSION_REVOKED, $refused->reason);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->tenant_id);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $row->revoked_reason);
    }

    /**
     * A policy change after a switch away from the tenant finds nothing of the
     * session to judge there: it stays active in the tenant it moved to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeAfterASwitchAwayLeavesTheSessionAlone(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $other   = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $target  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $session = $this->signIn($first);

        self::assertTrue($this->sessions('members')->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($target))->isSwitched());

        $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(IdentifierCoercion::stringify($other->getKey()), $row->tenant_id);
        self::assertNull($row->revoked_at);
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
     * Sign the seeded member in with its password, as the principal named, if
     * one is: a member with more than one membership must name one, or it is
     * held pending for the choice.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(?Principal $principal = null): SignedInSession
    {
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $principal))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Run the callback once, just before the next update of a session that
     * names the column executes, as another request that commits first would.
     *
     * @param  string  $column
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheUpdate(string $column, \Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($column, $callback, &$done): void {

            $statement = strtolower($query);

            if ($done || !str_starts_with($statement, 'update') || !str_contains($statement, $column)) {
                return;
            }

            $done = true;

            $callback();
        });
    }

    /**
     * Insert the given number of live sessions of the member's membership,
     * active in its tenant.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $membership
     * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @param  int  $count
     * @return void
     */
    private function insertSessions(ActivatableTenantMember $member, ActivatableTenantMembership $membership, ActivatableTenant $tenant, int $count): void
    {
        $rows = array_map(static fn (int $index): array => [
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $member->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($member->getKey()),
            'principal_type'       => $membership->getMorphClass(),
            'principal_id'         => IdentifierCoercion::stringify($membership->getKey()),
            'tenant_id'            => IdentifierCoercion::stringify($tenant->getKey()),
            'status'               => 'active',
            'guard'                => 'members',
            'sign_in_method'       => 'password',
            'refresh_key'          => hash('sha256', 'refresh-' . $index),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ], range(1, $count));

        foreach (array_chunk($rows, 200) as $chunk) {
            DB::table('authentication_sessions')->insert($chunk);
        }
    }

    /**
     * Bind a tenant authentication policy that answers every tenant with the
     * requirement and counts the sessions it judges, keeping none of them.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @return object{judged: int}&\SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy
     */
    private static function countingPolicy(TenantRequirement $requirement): TenantAuthenticationPolicy
    {
        $policy = new class ($requirement) implements TenantAuthenticationPolicy {
            /** @var int How many times it was asked. */
            public int $judged = 0;

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
             */
            public function __construct(

                /** The requirement it answers with. */
                private readonly TenantRequirement $requirement,
            ) {}

            /**
             * Count the question and answer with the requirement.
             *
             * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
             * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
             */
            #[\Override]
            public function requirementFor(TenantPolicyContext $context): TenantRequirement
            {
                $this->judged++;

                return $this->requirement;
            }
        };

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        return $policy;
    }

    /**
     * The table's name as the default connection's grammar quotes it, in lower
     * case as the statements are compared.
     *
     * @param  string  $table
     * @return string
     */
    private static function quoted(string $table): string
    {
        return strtolower(DB::connection()->getQueryGrammar()->wrapTable($table));
    }

    /**
     * Collect the statements run from now on that the filter keeps,
     * lower-cased.
     *
     * @param  \Closure(string): bool  $filter
     * @return \ArrayObject<int, string>
     */
    private function countQueries(\Closure $filter): \ArrayObject
    {
        $queries = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($queries, $filter): void {

            $sql = strtolower($query->sql);

            if (!$filter($sql)) {
                return;
            }

            $queries->append($sql);
        });

        return $queries;
    }
}
