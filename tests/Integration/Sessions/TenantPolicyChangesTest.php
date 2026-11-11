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
 * Integration tests of the policy-change helper against real rows.
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
     * Freeze the clocks, create the tables and bind the scripted policy.
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
     * Every session past two chunks is judged once, and the helper holds only
     * one chunk at a time.
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
        self::assertCount(TenantPolicyChanges::CHUNK, $policy->firstChunk);
        self::assertSame(0, $policy->firstChunkHeld);
        self::assertSame($count, DB::table('authentication_sessions')->where('tenant_policy_version', 'v1')->count());

        $updates = $this->countQueries(static fn (string $sql): bool => str_starts_with($sql, 'update'));

        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertCount(0, $updates);
    }

    /**
     * Every session past two chunks that falls short is revoked and reported
     * once.
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
     * The helper commits with the caller's transaction and reports only on
     * commit.
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
     * The helper rolls back with the caller's transaction and reports nothing.
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
     * A refresh losing to a policy change that revokes it fails as
     * `session_revoked`.
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

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertSame(FailureReason::SESSION_REVOKED, $refused->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A refresh losing to a recorded version is a retryable conflict.
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

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh(self::bodyToken($session->tokens), self::requestClient());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(FailureReason::ROTATION_CONFLICT, $refused->reason);
        self::assertSame('v9', $row->tenant_policy_version);
        self::assertSame($digest, $row->refresh_key);
        self::assertNull($row->revoked_at);
        self::assertTrue(
            self::sessionsOf($this->freshGuard('members'))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->isRefreshed(),
        );
    }

    /**
     * A switch losing to a policy change that revokes it fails as
     * `session_revoked`.
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

        $refused = $this->sessions('members')->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($target),
            self::requestClient(),
        );

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(FailureReason::SESSION_REVOKED, $refused->reason);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->tenant_id);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $row->revoked_reason);
    }

    /**
     * A policy change after a switch away leaves the session alone.
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

        self::assertTrue(
            $this->sessions('members')->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($target),
                self::requestClient(),
            )->isSwitched(),
        );

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
     * Sign the seeded member in with its password, as the principal if one is
     * given.
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
     * Run the callback once, just before the next session update that names the
     * column.
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
     * Insert live sessions of the member's membership, active in its tenant.
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
     * Bind a tenant policy that answers with the requirement and counts the
     * sessions it judges and still held.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @return object{judged: int, firstChunk: list<\WeakReference<object>>, firstChunkHeld: ?int}&\SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy
     */
    private static function countingPolicy(TenantRequirement $requirement): TenantAuthenticationPolicy
    {
        $policy = new class ($requirement) implements TenantAuthenticationPolicy {
            /** @var int How many times it was asked. */
            public int $judged = 0;

            /** @var list<\WeakReference<object>> The first chunk's sessions, referred to weakly. */
            public array $firstChunk = [];

            /** @var ?int How many of the first chunk's sessions were still held when the third chunk's first was judged. */
            public ?int $firstChunkHeld = null;

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
             * Count the question, track the first chunk weakly and answer with
             * the requirement.
             *
             * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
             * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
             */
            #[\Override]
            public function requirementFor(TenantPolicyContext $context): TenantRequirement
            {
                if ($this->judged === TenantPolicyChanges::CHUNK * 2) {
                    gc_collect_cycles();

                    $this->firstChunkHeld = count(array_filter($this->firstChunk, static fn (\WeakReference $session): bool => $session->get() !== null));
                }

                if ($this->judged < TenantPolicyChanges::CHUNK && $context->session !== null) {
                    $this->firstChunk[] = \WeakReference::create($context->session);
                }

                $this->judged++;

                return $this->requirement;
            }
        };

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        return $policy;
    }

    /**
     * The table name as the default grammar quotes it, lower-cased.
     *
     * @param  string  $table
     * @return string
     */
    private static function quoted(string $table): string
    {
        return strtolower(DB::connection()->getQueryGrammar()->wrapTable($table));
    }

    /**
     * Collect the lower-cased statements run from now on that the filter keeps.
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
