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
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\ReturnedToPending;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\TestCase;

/**
 * Feature tests for an active session's return to pending: the one
 * compare-and-swap on the row as it was loaded, what it records, the pending
 * credential it hands out, and its report once committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingTransitions::class)]
#[CoversClass(ReturnedToPending::class)]
final class PendingTransitionsTest extends TestCase
{
    use InteractsWithSessions, MarksSharedLocks;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
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
     * The session returns to pending on `mfa` with a new pending credential of
     * the configured lifetime, its floor moved to now, keeping its principal
     * and tenant and recording the policy version the caller judged it against,
     * the session given holding what was written as stored; the report follows,
     * naming no previous principal or tenant, since neither changed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionReturnsToPending(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->recordEvents([SessionReturnedToPending::class]);

        $requirement = new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2));
        $firstFactor = self::firstFactorOf($session);
        $admitted    = new Admitted($member, $membership, $tenant);
        $returned    = $this->transitions()->returnToPending($session, $admitted, 'v3', $requirement, $firstFactor, AuthenticationFlow::REFRESH, $this->now);

        self::assertNotNull($returned);
        self::assertSame([PendingRequirement::MFA], $returned->pending->requires);
        self::assertSame($requirement, $returned->pending->requirement);
        self::assertSame($firstFactor, $returned->pending->firstFactor);
        self::assertSame(ProofKind::FIRST_FACTOR, $returned->pending->firstFactor->kind);
        self::assertSame('password', $returned->pending->firstFactor->method);
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $returned->pending->expiresAt->getTimestamp());
        self::assertSame($session, $returned->pending->session);
        self::assertSame(SessionStatus::PENDING, $session->getStatus());
        self::assertSame([PendingRequirement::MFA], $session->getRequires());
        self::assertSame('v3', $session->getTenantPolicyVersion());
        self::assertFalse($session->isDirty());

        [$key, $secret] = explode('.', $returned->credential->reveal(), 2);

        self::assertSame(IdentifierCoercion::stringify($session->getKey()), $key);

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertTrue(RefreshTokenHasher::verify($secret, (string) $row->getPendingKey()));
        self::assertSame($this->now->getTimestamp(), $row->getSwitchedAt()?->getTimestamp());
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());
        self::assertSame('v3', $row->getTenantPolicyVersion());

        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(AuthenticationFlow::REFRESH, $event->flow);
        self::assertNull($event->previousPrincipalId);
        self::assertNull($event->previousPrincipalType);
        self::assertNull($event->previousTenantId);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$event->context->client->ip, $event->context->client->userAgent]);
    }

    /**
     * Transitions built with a client report a return with that client, not the
     * guard's request's: a refresh from plain values reports its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnIsReportedWithTheClientTheTransitionsWereGiven(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $client  = new ClientContext('192.0.2.44', 'Plain/1.0');

        $this->recordEvents([SessionReturnedToPending::class]);

        $returned = $this->transitions('members', $client)->returnToPending(
            $session,
            new Admitted($member, $membership, $tenant),
            'v3',
            self::requirement(),
            self::firstFactorOf($session),
            AuthenticationFlow::REFRESH,
            $this->now,
        );

        self::assertNotNull($returned);
        self::assertSame($client, $this->recordedEvent(SessionReturnedToPending::class)->context->client);
    }

    /**
     * Transitions that report through a schedule hand it each return's report
     * once the return applied, in place of scheduling it for the commit, with
     * the client they were given, and keep the client when they are made;
     * nothing is handed over for a return that did not apply.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnIsReportedThroughTheScheduleTheTransitionsWereGiven(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();
        $client  = new ClientContext('192.0.2.44', 'Plain/1.0');
        /** @var \ArrayObject<int, \Closure(): void> $reports */
        $reports  = new \ArrayObject;
        $schedule = static function (\Closure $report) use ($reports): void {
            $reports->append($report);
        };

        $this->recordEvents([SessionReturnedToPending::class]);

        $transitions = $this->transitions('members', $client)->reportingThrough($schedule);
        $admitted    = new Admitted($member, $membership, $tenant);
        $returned    = $transitions->returnToPending($session, $admitted, 'v3', self::requirement(), self::firstFactorOf($session), AuthenticationFlow::REFRESH, $this->now);

        self::assertNotNull($returned);
        self::assertCount(1, $reports);
        self::assertSame([], $this->recordedClasses());

        foreach ($reports as $report) {
            $report();
        }

        self::assertSame($client, $this->recordedEvent(SessionReturnedToPending::class)->context->client);

        $missed = $transitions->returnToPending($session, $admitted, 'v3', self::requirement(), self::firstFactorOf($session), AuthenticationFlow::REFRESH, $this->now);

        self::assertNull($missed);
        self::assertCount(1, $reports);
    }

    /**
     * What an active session falls short of is the tenant's requirement alone
     * while the identity owes nothing, and the strictest of both once the
     * identity's own factor policy asks for more than the session has, judged
     * on the session as it records its sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatASessionFallsShortOfIsTheStrictestOfTheTenantsAndTheIdentitys(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();
        $tenant  = new Requirement(multifactor: new RequirementPart(300));

        $first = self::firstFactorOf($session);

        self::assertEquals($tenant, $this->transitions()->outstanding($session, $member, $tenant, $first, $this->now));

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $outstanding = $this->transitions()->outstanding($session, $member, $tenant, $first, $this->now);

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MULTIFACTOR], $outstanding->kinds());
        self::assertSame(300, $outstanding->multifactor?->maxAgeSeconds);
    }

    /**
     * Asked to read current, as a caller holding the session's row locked asks,
     * the first factor a return to pending is judged on, when the verdict
     * carries none, and the proofs what the session falls short of is judged on
     * are read with a shared lock where the engine takes one; asked nothing,
     * they are read plainly.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionsProofsAreReadCurrentOnlyWhenAsked(): void
    {
        self::markSharedLocks();

        [$member] = $this->seedMember();

        $session = $this->signedIn();
        $first   = self::firstFactorOf($session);
        $met     = new TenantPolicyVerdict(TenantPolicyStanding::MET, 'v1');
        $locked  = self::takesSharedLocks();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $transitions = $this->transitions();

        self::assertSame([$locked], self::proofReadLocks(static fn (): mixed => PendingTransitions::firstFactorOf($session, $met, true)));
        self::assertSame([false], self::proofReadLocks(static fn (): mixed => PendingTransitions::firstFactorOf($session, $met)));
        self::assertSame([$locked], self::proofReadLocks(fn (): mixed => $transitions->outstanding($session, $member, new Requirement, $first, $this->now, true)));
        self::assertSame([false], self::proofReadLocks(fn (): mixed => $transitions->outstanding($session, $member, new Requirement, $first, $this->now)));
    }

    /**
     * The first factor a return to pending is judged on is the one the tenant's
     * verdict was judged on, with no further read, and otherwise the one the
     * session records, read once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFactorIsTheVerdictsElseTheSessionsOwn(): void
    {
        $this->seedMember();

        $session = $this->signedIn();
        $judged  = self::firstFactorOf($session);

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        self::assertSame($judged, PendingTransitions::firstFactorOf($session, new TenantPolicyVerdict(TenantPolicyStanding::FACTOR_REQUIRED, 'v1', self::requirement(), $judged)));
        self::assertCount(0, $statements);

        $recorded = PendingTransitions::firstFactorOf($session, new TenantPolicyVerdict(TenantPolicyStanding::MET, 'v1'));

        self::assertNotSame($judged, $recorded);
        self::assertSame([$judged->id, ProofKind::FIRST_FACTOR], [$recorded->id, $recorded->kind]);
        self::assertCount(1, $statements);
    }

    /**
     * A session acting in no tenant returns to pending in none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionInNoTenantReturnsToPendingInNone(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $session);

        $returned = $this->transitions('api')->returnToPending(
            $session,
            new Admitted($identity, $identity, null),
            null,
            self::requirement(),
            self::firstFactorOf($session),
            AuthenticationFlow::REFRESH,
            $this->now,
        );

        self::assertNotNull($returned);
        self::assertNull($returned->pending->tenant);

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertNull($row->getTenantId());
    }

    /**
     * A destination of another principal and tenant records them and reports
     * the ones the session left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationElsewhereReportsWhatTheSessionLeft(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        [, $elsewhere, $other] = $this->seedMember('second@example.test');

        $this->recordEvents([SessionReturnedToPending::class]);

        $admitted = new Admitted($member, $elsewhere, $other);
        $returned = $this->transitions()->returnToPending($session, $admitted, null, self::requirement(), self::firstFactorOf($session), AuthenticationFlow::REFRESH, $this->now);

        self::assertNotNull($returned);

        $row   = Session::query()->sole();
        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(IdentifierCoercion::stringify($elsewhere->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($other->getKey()), $row->getTenantId());
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $event->previousPrincipalId);
        self::assertSame($membership->getMorphClass(), $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $event->previousTenantId);
    }

    /**
     * A session returned to pending in another tenant records the version that
     * tenant's policy answered, not the one its old tenant's did, so the new
     * tenant's policy-change helper never takes it as already checked when the
     * two tenants answer the same version: the destination coming to require a
     * connection at the version the origin recorded revokes it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnElsewhereRecordsTheDestinationsVersion(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $session->getKey())->update(['tenant_policy_version' => 'v2']);

        $session = Session::query()->sole();

        [, $elsewhere, $other] = $this->seedMember('second@example.test');

        $admitted = new Admitted($member, $elsewhere, $other);
        $returned = $this->transitions()->returnToPending($session, $admitted, 'v1', self::requirement(), self::firstFactorOf($session), AuthenticationFlow::SWITCH, $this->now);

        self::assertNotNull($returned);
        self::assertSame('v1', Session::query()->sole()->getTenantPolicyVersion());

        $origin = IdentifierCoercion::stringify($tenant->getKey());

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', connections: ['conn-a'])));

        self::assertNotSame($origin, Session::query()->sole()->getTenantId());
        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($other));
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, Session::query()->sole()->getRevokedReason());
    }

    /**
     * Rows of `[change]`, one per predicate of the compare-and-swap, that a
     * write between the load and the swap makes to the session's row.
     *
     * @return iterable<string, array{0: array<string, ?string>}>
     */
    public static function provideChangesSinceTheLoad(): iterable
    {
        yield 'rotated' => [['refresh_key' => hash('sha256', 'rotated')]];
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'revoked']];
        yield 'pending' => [['status' => 'pending', 'requires' => '["mfa"]']];
        yield 'another principal' => [['principal_id' => '999999']];
        yield 'another principal type' => [['principal_type' => 'another-type']];
        yield 'another tenant' => [['tenant_id' => 'elsewhere']];
        yield 'a version recorded' => [['tenant_policy_version' => 'v9']];
        yield 'a moved idle deadline' => [['idle_expires_at' => '2026-04-07 12:00:00']];
        yield 'a moved absolute deadline' => [['absolute_expires_at' => '2026-10-06 12:00:00']];
    }

    /**
     * A row that changed in any column the compare-and-swap holds since it was
     * loaded is left exactly as it is, nothing is reported, and the caller
     * judges it again: each of its predicates refuses the swap on its own.
     *
     * @param  array<string, ?string>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesSinceTheLoad')]
    public function testARowChangedSinceItWasLoadedIsLeftAlone(array $change): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $session->getKey())->update($change);

        $row = (array) DB::table('authentication_sessions')->sole();

        $this->recordEvents([SessionReturnedToPending::class]);

        $admitted = new Admitted($member, $membership, $tenant);
        $returned = $this->transitions()->returnToPending($session, $admitted, 'v3', self::requirement(), self::firstFactorOf($session), AuthenticationFlow::REFRESH, $this->now);

        self::assertNull($returned);
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
        self::assertSame([], $this->recordedClasses());
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
     * The transitions of the guard, the members' unless another is named,
     * reporting with the client given, if any.
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingTransitions
     */
    private function transitions(string $guard = 'members', ?ClientContext $client = null): PendingTransitions
    {
        return new PendingTransitions($this->freshGuard($guard)->context(), new AfterCommit(static fn (): mixed => app('db.transactions')), app(ConfigRepository::class), $client);
    }

    /**
     * Sign the seeded member in with its password and return its session.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(): Session
    {
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }

    /**
     * The first factor the session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function firstFactorOf(Session $session): RecordedProof
    {
        return PendingEvaluation::firstFactorOf($session);
    }

    /**
     * A requirement of a further factor, as a policy that returns a session to
     * pending falls short of.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function requirement(): Requirement
    {
        return new Requirement(new RequirementPart);
    }
}
