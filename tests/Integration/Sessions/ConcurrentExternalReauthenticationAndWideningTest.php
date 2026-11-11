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
 * Races an external reauthentication against the widening of its link's scope,
 * each in its own process.
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
     * Skip where processes cannot share the database, freeze the clocks and
     * create the tables.
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
     * A reauthentication that locks first commits its proof and is then
     * revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationThatLocksFirstCommitsAndIsThenRevoked(): void
    {
        [$identity, $session] = $this->signedInExternally();

        $outcome = $this->race(
            fn (): mixed => $this->sessions()->reauthenticateExternally($session->getKey(), $this->throughTheLink(), self::requestClient())->isIssued(),
            fn (): mixed => DB::transaction(fn (): int => $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1')),
        );

        self::assertSame([true, 1], $outcome);
        self::assertSame(1, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
        self::assertSame('link_scope_widened', DB::table('authentication_sessions')->where('id', $session->getKey())->value('revoked_reason'));
    }

    /**
     * A widening that locks first leaves the reauthentication revoked with no
     * proof.
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
            fn (): mixed => $this->sessions()->reauthenticateExternally($session->getKey(), $this->throughTheLink(), self::requestClient())->reason?->value,
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
     * Run the first side in an open transaction until the forked second is
     * about to lock a row, then commit it.
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
     * Signal that the second side is about to run a locking read.
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
     * Sign the seeded identity in through its link and move the clocks on an
     * hour.
     *
     * @return array{0: \Tests\Integration\Fixtures\IntegrationIdentity, 1: \SineMacula\Laravel\Authentication\Models\Session}
     *
     * @throws \Throwable
     */
    private function signedInExternally(): array
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally(
            $this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->start),
            self::requestContext(),
        )->session?->record;

        self::assertInstanceOf(Session::class, $session);

        $this->freezeAt($this->start->addHour());

        return [$identity, $session];
    }

    /**
     * A result through the seeded identity's link, authenticated now.
     *
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    private function throughTheLink(): ExternalResult
    {
        return new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: CarbonImmutable::now());
    }

    /**
     * Run the second side in the forked process, report its outcome and exit
     * without the parent's shutdown.
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
     * Wait, up to the timeout, for the other side to create the signal file.
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
     * Fail the unstarted race, rolling back the first side and reaping the
     * second so neither holds locks.
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
