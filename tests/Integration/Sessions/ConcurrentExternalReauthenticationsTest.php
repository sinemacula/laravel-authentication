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
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races two external reauthentications of one session, each in its own process,
 * so the later provider time wins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalReauthentication::class)]
final class ConcurrentExternalReauthenticationsTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithSessions;

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

        $this->outcomes = sys_get_temp_dir() . '/external-reauthentication-race-' . bin2hex(random_bytes(8));

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
     * The later provider time wins whichever side commits last.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLaterProviderTimeWinsWhicheverCommitsLast(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally(
            $this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->start),
            self::requestContext(),
        )->session?->record;

        self::assertInstanceOf(Session::class, $session);

        $this->freezeAt($this->start->addHour());

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($session): array {
                $this->externalLinks()->whileAsked(function (): void {
                    touch("{$this->outcomes}/locking");
                });

                return self::authenticationTimeOf($this->reauthenticate($session, $this->start->addMinutes(10)));
            });
        }

        DB::beginTransaction();

        $first = self::authenticationTimeOf($this->reauthenticate($session, $this->start->addMinutes(50)));

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/locking")) {
            self::abandon($pid, 'The second side never reached the session\'s lock, so the reauthentications did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);
        self::assertSame([$this->start->addMinutes(50)->getTimestamp(), true], $first);
        self::assertSame([$this->start->addMinutes(50)->getTimestamp(), true], $reported['result']);
        self::assertSame(2, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
    }

    /**
     * The later provider time wins inside a caller's REPEATABLE READ
     * transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLaterProviderTimeWinsInsideACallersRepeatableReadTransaction(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally(
            $this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->start),
            self::requestContext(),
        )->session?->record;

        self::assertInstanceOf(Session::class, $session);

        $this->freezeAt($this->start->addHour());

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($session): array {
                $this->externalLinks()->whileAsked(function (): void {
                    touch("{$this->outcomes}/locking");
                });

                $reauthenticate = fn (): array => self::authenticationTimeOf($this->reauthenticate($session, $this->start->addMinutes(10)));

                self::beginTransactionAt('repeatable read');

                DB::table('authentication_proofs')->count();

                $failed = null;

                try {
                    $result = $reauthenticate();
                } catch (DeadlockException $exception) {
                    $failed = (string) $exception->getPrevious()?->getCode();

                    DB::rollBack();

                    self::beginTransactionAt('repeatable read');

                    $result = $reauthenticate();
                }

                DB::commit();

                return ['time' => $result, 'failed' => $failed];
            });
        }

        DB::beginTransaction();

        $first = self::authenticationTimeOf($this->reauthenticate($session, $this->start->addMinutes(50)));

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/locking")) {
            self::abandon($pid, 'The second side never reached the session\'s lock, so the reauthentications did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertSame([$this->start->addMinutes(50)->getTimestamp(), true], $first);
        self::assertSame(self::readsASnapshot('repeatable read') ? '40001' : null, $reported['result']['failed']);
        self::assertSame([$this->start->addMinutes(50)->getTimestamp(), true], $reported['result']['time']);
        self::assertSame(2, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
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
     * The `auth_time` of the access token a reauthentication issued, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @return array{0: mixed, 1: bool}
     */
    private static function authenticationTimeOf(AccessTokenResult $result): array
    {
        $claims = $result->accessToken === null ? [] : Auth::manager()->jwt('api')->parse($result->accessToken->reveal(), TokenType::ACCESS);

        return [is_array($claims) ? $claims['auth_time'] ?? null : null, $result->isIssued()];
    }

    /**
     * Reauthenticate the session through its link at the given provider time.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    private function reauthenticate(Session $session, CarbonImmutable $at): AccessTokenResult
    {
        return $this->sessions()->reauthenticateExternally(
            $session->getKey(),
            new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $at),
            self::requestClient(),
        );
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
