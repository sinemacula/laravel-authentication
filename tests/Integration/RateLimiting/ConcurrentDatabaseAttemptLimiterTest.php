<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore;
use Tests\TestCase;

/**
 * Races the limiter against itself across processes, each with its own database
 * connection, on PostgreSQL and MySQL: however the attempts interleave, no more
 * than the limit are granted and no failure is lost.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class ConcurrentDatabaseAttemptLimiterTest extends TestCase
{
    /** @var int Processes racing in each test. */
    private const int PROCESSES = 12;

    /** @var int Sign-in attempts allowed per identifier in the window. */
    private const int MAX = 5;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, and freeze the clock so
     * every process counts in the same window.
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

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000150));

        $this->outcomes = sys_get_temp_dir() . '/limiter-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Release the clock and remove the outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * Attempts racing for one identifier's first window are granted exactly up
     * to the limit, the counter's creation race included.
     *
     * @return void
     */
    public function testRacingSignInsNeverExceedTheLimit(): void
    {
        $outcomes = $this->race(fn (): string => $this->limiter()->acquire($this->subject(AttemptFlow::SIGN_IN))->granted() ? 'granted' : 'refused');

        self::assertCount(self::MAX, array_keys($outcomes, 'granted', true));
        self::assertCount(self::PROCESSES - self::MAX, array_keys($outcomes, 'refused', true));
        self::assertEquals(self::MAX, DB::table('rate_limits')->value('hits'));
    }

    /**
     * Failures racing for one device are each counted once.
     *
     * @return void
     */
    public function testRacingFailuresAreAllCounted(): void
    {
        $outcomes = $this->race(function (): string {
            $this->limiter()->recordFailure($this->subject(AttemptFlow::REFRESH));

            return 'recorded';
        });

        self::assertSame(array_fill(0, self::PROCESSES, 'recorded'), $outcomes);
        self::assertEquals(self::PROCESSES, DB::table('rate_limits')->value('hits'));
    }

    /**
     * Configure limits on the identifier only.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'users',
            'rate_limits' => [
                'sign_in' => ['per_identifier' => ['max' => self::MAX, 'decay_seconds' => 300], 'per_ip' => null],
                'refresh' => ['per_identifier' => ['max' => 1, 'decay_seconds' => 300], 'per_ip' => null],
            ],
        ]);
    }

    /**
     * Fork the processes, have each run the attempt at the same moment on a
     * connection of its own, and collect what each reported.
     *
     * @param  \Closure(): string  $attempt
     * @return list<string>
     */
    private function race(\Closure $attempt): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $attempt);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: wait for the start, make the attempt, report its
     * outcome, and end without running the parent's shutdown.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(): string  $attempt
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $attempt): never
    {
        try {
            time_sleep_until($start);

            $outcome = $attempt();
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
    }

    /**
     * The attempt every process makes.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function subject(AttemptFlow $flow): AttemptSubject
    {
        return new AttemptSubject('api', $flow, 'ben@example.com', 'email', '203.0.113.7');
    }
}
