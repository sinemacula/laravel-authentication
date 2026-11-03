<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races an external reauthentication of a session against the widening of the
 * scope of the link that established it, on PostgreSQL and MySQL, each side in
 * a process with a database connection of its own. Both lock the session's row
 * (the reauthentication last, after the link contract; the widening when it
 * revokes), so they never interleave: whichever holds the row first commits,
 * and the other, which waited on it, then sees what it committed. A
 * reauthentication that commits first records its proof and the widening then
 * revokes the session (its new token dies at its next request, as every token
 * of a revoked session does); a widening that commits first leaves the
 * reauthentication `session_revoked`, with no proof recorded.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalReauthentication::class)]
#[CoversClass(ConnectionRevocations::class)]
final class ConcurrentExternalReauthenticationAndWideningTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var int How long the first side holds its lock once the second is about to take it, in microseconds. */
    private const int SETTLE_MICROSECONDS = 300000;

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var \Carbon\CarbonImmutable When the session began. */
    private CarbonImmutable $start;

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, and create the tables.
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

        $this->start = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->freezeAt($this->start);

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/external-widening-race-' . bin2hex(random_bytes(8));

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
     * A reauthentication holding the session's row makes the widening wait;
     * once it commits, its proof stands and the widening revokes the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationThatLocksFirstCommitsAndIsThenRevoked(): void
    {
        [$identity, $session] = $this->signedInExternally();

        $outcome = $this->race(
            fn (): mixed => $this->sessions()->reauthenticateExternally($session, $this->throughTheLink())->isIssued(),
            fn (): mixed => DB::transaction(fn (): int => $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1')),
        );

        self::assertSame([true, 1], $outcome);
        self::assertSame(1, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
        self::assertSame('link_scope_widened', DB::table('authentication_sessions')->where('id', $session->getKey())->value('revoked_reason'));
    }

    /**
     * A widening holding the session's row makes the reauthentication wait;
     * once it commits, the reauthentication finds the session revoked and
     * records nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningThatLocksFirstLeavesTheReauthenticationRevoked(): void
    {
        [$identity, $session] = $this->signedInExternally();

        $outcome = $this->race(
            fn (): mixed => $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1'),
            fn (): mixed => $this->sessions()->reauthenticateExternally($session, $this->throughTheLink())->reason?->value,
        );

        self::assertSame([1, FailureReason::SESSION_REVOKED->value], $outcome);
        self::assertSame(0, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
    }

    /**
     * Register the guards.
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
     * Run the first side inside a transaction it holds open until the second,
     * forked, is about to lock a row, then commit it: what each answered, the
     * first's first. The second must have waited on the first.
     *
     * @param  \Closure(): mixed  $first
     * @param  \Closure(): mixed  $second
     * @return array{0: mixed, 1: mixed}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($second): mixed {
                DB::connection()->beforeExecuting($this->signalLocking(...));

                return $second();
            });
        }

        DB::beginTransaction();

        $answered = $first();

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/locking")) {
            self::abandon($pid, 'The second side never reached a lock, so the two did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);

        return [$answered, $reported['result']];
    }

    /**
     * Signal that the second side is about to lock a row, when the query it is
     * about to run is a locking read.
     *
     * @param  string  $query
     * @return void
     */
    private function signalLocking(string $query): void
    {
        if (stripos($query, 'for update') === false) {
            return;
        }

        touch("{$this->outcomes}/locking");
    }

    /**
     * Sign the seeded identity in through its link, `link-1` of `connection-7`,
     * and move the clocks on an hour.
     *
     * @return array{0: \Tests\Integration\Fixtures\IntegrationIdentity, 1: \SineMacula\Laravel\Authentication\Models\Session}
     *
     * @throws \Throwable
     */
    private function signedInExternally(): array
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->start))->session?->record;

        self::assertInstanceOf(Session::class, $session);

        $this->freezeAt($this->start->addHour());

        return [$identity, $session];
    }

    /**
     * A result through the seeded identity's link, the provider authenticating
     * it now.
     *
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    private function throughTheLink(): ExternalResult
    {
        return new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: CarbonImmutable::now());
    }

    /**
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): mixed  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        $outcome = ['error' => 'The first side never signalled the start.'];

        try {
            if (self::wasSignalled("{$this->outcomes}/start")) {
                $started = microtime(true);
                $result  = $second();
                $outcome = ['result' => $result, 'waited' => microtime(true) - $started];
            }
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait for the other side to create the signal file, for no longer than the
     * timeout: whether it did.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function wasSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        while (!is_file($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }

        return is_file($signal);
    }

    /**
     * Fail the race that was never set up: roll the first side's transaction
     * back and stop and reap the second side, so neither is left holding locks
     * on the tables the teardown drops.
     *
     * @param  positive-int  $pid
     * @param  string  $message
     * @return never
     */
    private static function abandon(int $pid, string $message): never
    {
        DB::rollBack();

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);

        self::fail($message);
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
