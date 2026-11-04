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
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;

/**
 * Feature tests of the policy-change helper's edges through the session
 * service, against a real database: a tenant without an identifier, sessions
 * whose owner or principal no longer loads, a met session already recorded at
 * the version answered, a session that changed between the locking read and the
 * write, and sessions that have already ended.
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
    use InteractsWithSessions, MarksSharedLocks;

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
     * A tenant whose identifier names no tenant has no sessions to judge: the
     * helper revokes nothing, asks the policy nothing and reads nothing.
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
     * The tables whose row a session's actors are read from: the principal's,
     * and the owning identity's.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideActorTables(): iterable
    {
        yield 'the principal' => ['activatable_tenant_memberships'];
        yield 'the owner' => ['activatable_tenant_members'];
    }

    /**
     * A session whose owner or principal no longer loads lacks what the policy
     * is asked about, so it is judged short without asking: an active one is
     * revoked and reported, naming the owner, principal and tenant the row
     * records, with the session holding its revocation; a pending one is left
     * for its activation, which would refuse it.
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
     * A session that meets a policy answering no version, and records none, is
     * judged (a `null` version is never taken as already checked) but nothing
     * is written: the version it would record is the one it records.
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
     * A session revoked between the helper's read and its write is not revoked
     * again: the conditional update finds nothing, so the first revocation
     * stands, the session is not counted and nothing is reported.
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
     * keeps the version it records: the conditional update finds it acting
     * elsewhere and writes nothing.
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
     * Every session row is locked before any proof is read: the keys of the
     * tenant's live sessions are read with a locking read, then those sessions
     * again with one, and only then is each judged, every read of its proofs
     * taking a shared lock where the engine takes one. The sessions judged are
     * those the keys named: one that enters the tenant after they were read is
     * left as it is.
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
     * Only live sessions are judged: one whose idle or absolute deadline has
     * come (at this very second, or before) has already ended, so it is neither
     * judged, revoked, counted nor reported, and is left for pruning.
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
     * A session that records no guard is judged for none, the policy asked
     * about the empty application name, and revoked when it falls short, its
     * report naming no guard.
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
     * Sign the seeded member in with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * A pending session of the seeded member in its tenant, waiting on a
     * further factor its tenant asked for at sign-in, and its key; the policy
     * is put back as it was.
     *
     * @return mixed
     *
     * @throws \Throwable
     */
    private function pendingFor(): mixed
    {
        $requirement = $this->policy->requirement;

        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart));

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

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
