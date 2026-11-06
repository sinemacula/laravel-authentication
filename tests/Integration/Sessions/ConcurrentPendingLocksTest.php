<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DeadlockException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;

/**
 * Races the calls that lock a pending session's row on PostgreSQL and MySQL,
 * each in a process with a database connection of its own: one holds the lock
 * inside a transaction it keeps open, and the other, started meanwhile, waits
 * on that lock and then judges the row the first committed. A satisfaction and
 * a discard never both apply; a policy change and an activation each see the
 * other's result, so the session ends compliant either way. A satisfaction that
 * deadlocks inside a caller's transaction fails as a deadlock the caller can
 * retry whole.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(SessionActivation::class)]
#[CoversClass(TenantPolicyChanges::class)]
final class ConcurrentPendingLocksTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var int How long the first call holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second call must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the forked side waits, once the satisfaction waits on the proven session, before it asks for the pending one, in microseconds: under PostgreSQL's one-second deadlock check, so the satisfaction, which has waited longer, is the side that finds the cycle. */
    private const int CROSS_MICROSECONDS = 300000;

    /** @var int How long the second call waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second call reports its outcome in. */
    private string $outcomes;

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy tenants answer with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, create the tables, require a further factor of
     * every sign-in, and bind the scripted tenant policy.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->policy = new ScriptedTenantAuthenticationPolicy;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);

        $this->outcomes = sys_get_temp_dir() . '/pending-lock-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A satisfaction that waits on a discard holding the session's lock finds
     * the session ended once the discard commits, and fails as
     * `pending_invalid`, storing no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionWaitingOnADiscardFindsTheSessionEnded(): void
    {
        $this->seedMember();

        [$credential, $proof] = $this->pendingSession();

        $proofs = SessionProof::query()->count();

        [$discarded, $second] = $this->race(
            fn (): bool => $this->sessions(self::GUARD)->discard($credential),
            fn (): array => ['reason' => $this->sessions(self::GUARD)->satisfy($credential, $proof, self::requestClient())->reason?->value],
        );

        self::assertTrue($discarded);
        self::assertSame(FailureReason::PENDING_INVALID->value, $second['reason']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(RevocationReason::SIGNED_OUT->value, DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertSame($proofs, SessionProof::query()->count());
    }

    /**
     * A discard that waits on a satisfaction holding the session's lock finds
     * the session active once the satisfaction commits, and discards nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADiscardWaitingOnASatisfactionFindsTheSessionActive(): void
    {
        $this->seedMember();

        [$credential, $proof] = $this->pendingSession();

        [$satisfied, $second] = $this->race(
            fn (): bool => $this->sessions(self::GUARD)->satisfy($credential, $proof, self::requestClient())->isSignedIn(),
            fn (): array => ['discarded' => $this->sessions(self::GUARD)->discard($credential)],
        );

        self::assertTrue($satisfied);
        self::assertFalse($second['discarded']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertNull($row->revoked_at);
    }

    /**
     * A satisfaction that waits on a policy change holding the tenant's session
     * locks finds the session revoked once the change commits (its tenant now
     * requires a connection it can never meet), and fails as `pending_invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionWaitingOnAPolicyChangeFindsTheSessionRevoked(): void
    {
        [, , $tenant] = $this->seedMember();

        [$credential, $proof] = $this->pendingSession();

        $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

        [$revoked, $second] = $this->race(
            fn (): int => $this->sessions(self::GUARD)->tenantPolicyChanged($tenant),
            fn (): array => ['reason' => $this->sessions(self::GUARD)->satisfy($credential, $proof, self::requestClient())->reason?->value],
        );

        self::assertSame(1, $revoked);
        self::assertSame(FailureReason::PENDING_INVALID->value, $second['reason']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A policy change that waits on an activation holding the session's lock
     * reads the session the activation committed, recorded at the version it
     * was checked against, and judges it against the policy now published,
     * revoking it when it falls short.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeWaitingOnAnActivationJudgesTheActivatedSession(): void
    {
        [, , $tenant] = $this->seedMember();

        [$credential, $proof] = $this->pendingSession();

        $this->policy->requirement = new TenantRequirement('v1');

        [$activated, $second] = $this->race(
            fn (): bool => $this->sessions(self::GUARD)->satisfy($credential, $proof, self::requestClient())->isSignedIn(),
            function (ActivatableTenant $tenant): array {

                $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

                return ['revoked' => $this->sessions(self::GUARD)->tenantPolicyChanged($tenant)];
            },
            $tenant,
        );

        self::assertTrue($activated);
        self::assertSame(1, $second['revoked']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame('v1', $row->tenant_policy_version);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $row->revoked_reason);
    }

    /**
     * A satisfaction inside a caller's transaction that deadlocks on the
     * session its sign-in proved (another transaction wrote that session, then
     * asks for the pending one the satisfaction holds) is thrown on as
     * Laravel's `DeadlockException` with the caller's transaction level
     * restored: the package rolls nothing back to its savepoint, which on MySQL
     * the deadlock has already dropped with the whole transaction. The caller
     * rolls back, nothing the satisfaction wrote is kept, and its retry of the
     * whole transaction activates the session and supersedes the proven one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionDeadlockedInsideACallersTransactionIsThrownOnAsADeadlock(): void
    {
        $this->seedMember();

        [$first, $proof] = $this->pendingSession();

        $active = $this->sessions(self::GUARD)->satisfy($first, $proof, self::requestClient())->session;

        self::assertNotNull($active);

        $client = new SignInContext(new ClientContext('203.0.113.7', 'Racing client'), refreshToken: $active->tokens->refreshToken?->reveal());
        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $client);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $pending    = $result->pending;
        $credential = $result->credential->reveal();
        $proof      = static fn (): ProofResult => self::adapterProof($pending->identity, self::GUARD, $pending->id, Purpose::SIGN_IN);
        $proven     = $active->record->getKey();
        $proofs     = SessionProof::query()->count();

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->crossInChild($proven, $pending->id);
        }

        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!is_file("{$this->outcomes}/held") && microtime(true) < $deadline) {
            usleep(5000);
        }

        if (!is_file("{$this->outcomes}/held")) {
            posix_kill($pid, SIGKILL);
            pcntl_waitpid($pid, $status);

            self::fail('The forked side never held the proven session.');
        }

        DB::beginTransaction();

        try {
            $thrown = $this->sessions(self::GUARD)->satisfy($credential, $proof(), self::requestClient());
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        $level = DB::transactionLevel();

        DB::rollBack();

        pcntl_waitpid($pid, $status);

        self::assertSame(['crossed' => true], json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR));
        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame(1, $level);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame($proofs, SessionProof::query()->count());
        self::assertSame('pending', DB::table('authentication_sessions')->where('id', $pending->id)->value('status'));

        self::assertTrue(DB::transaction(fn (): bool => $this->sessions(self::GUARD)->satisfy($credential, $proof(), self::requestClient())->isSignedIn()));
        self::assertSame(RevocationReason::SUPERSEDED->value, DB::table('authentication_sessions')->where('id', $proven)->value('revoked_reason'));
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the seeded member in, which the factor policy holds pending, and
     * return its credential and an accepted further factor's proof bound to it.
     *
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     *
     * @throws \Throwable
     */
    private function pendingSession(): array
    {
        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'));

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        return [$result->credential->reveal(), self::adapterProof($result->pending->identity, self::GUARD, $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * Run the first call here inside a transaction, start the second in another
     * process once the first has taken its locks, hold the transaction open
     * while the second waits on them, then commit, and return the first's
     * outcome and the second's, with how long it waited.
     *
     * @param  \Closure(): mixed  $first
     * @param  \Closure(mixed): array<string, mixed>  $second
     * @param  mixed  ...$arguments
     * @return array{0: mixed, 1: array<array-key, mixed>}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, mixed ...$arguments): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second, $arguments);
        }

        DB::beginTransaction();

        $outcome = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);

        return [$outcome, $reported];
    }

    /**
     * In the forked process: on a connection of its own, write the proven
     * session in a transaction, several times so its transaction is the heavier
     * and MySQL picks the other as the deadlock's victim, signal that it holds
     * it, wait until the parent's satisfaction, having locked the pending
     * session, waits on the proven one, then ask for the pending one, closing
     * the cycle; once the database has failed the parent, roll back, report,
     * and end without running the parent's shutdown. A satisfaction that never
     * waits is reported as an error.
     *
     * @param  mixed  $proven
     * @param  mixed  $pending
     * @return never
     */
    private function crossInChild(mixed $proven, mixed $pending): never
    {
        try {
            DB::beginTransaction();

            foreach (range(1, 5) as $ignored) {
                DB::table('authentication_sessions')->where('id', $proven)->increment('issuance_sequence');
            }

            touch("{$this->outcomes}/held");

            self::awaitAWaiter();

            usleep(self::CROSS_MICROSECONDS);

            DB::table('authentication_sessions')->where('id', $pending)->lockForUpdate()->first();
            DB::rollBack();

            $outcome = ['crossed' => true];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until another connection waits on a lock this connection's
     * transaction holds, for as long as a call waits to be started.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function awaitAWaiter(): void
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!self::isWaitedOn()) {
            if (microtime(true) >= $deadline) {
                throw new \RuntimeException('Nothing waited on the locks this side holds.');
            }

            usleep(5000);
        }
    }

    /**
     * Whether another connection waits on a lock this connection's transaction
     * holds, as the engine's lock-wait view reports it. PostgreSQL's is read
     * from `pg_locks`, because `pg_stat_activity` keeps the backends of its
     * first read in a transaction, before the waiter has connected.
     *
     * @return bool
     */
    private static function isWaitedOn(): bool
    {
        return DB::connection()->getDriverName() === 'pgsql'
            ? DB::table('pg_locks')
                ->where('granted', false)
                ->whereRaw('pg_backend_pid() = any(pg_blocking_pids(pid))')
                ->exists()
            : DB::table('performance_schema.data_lock_waits as waits')
                ->join('performance_schema.threads as threads', 'threads.THREAD_ID', '=', 'waits.BLOCKING_THREAD_ID')
                ->whereRaw('threads.PROCESSLIST_ID = connection_id()')
                ->exists();
    }

    /**
     * In the forked process: wait to be started, run the call on a connection
     * of its own, report its outcome and how long it took, and end without
     * running the parent's shutdown.
     *
     * @param  \Closure(mixed): array<string, mixed>  $call
     * @param  list<mixed>  $arguments
     * @return never
     */
    private function runInChild(\Closure $call, array $arguments): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = [...$call(...$arguments), 'waited' => 0.0];

            $outcome['waited'] = microtime(true) - $started;
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
