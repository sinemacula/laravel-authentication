<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodes;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Fixtures\Codes\RecordingFactorCodeCounters;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Races two wrong guesses at a factor code's last attempt through
 * `verifyFactorCode()` on PostgreSQL and MySQL, each in a process with a
 * database connection of its own: the first holds its transaction open while
 * the second, started meanwhile, has been admitted by the counters and waits on
 * the challenge's row. The attempts never pass `max_attempts`, and the counters
 * are told of each counted attempt exactly once, in the transaction that
 * counted it.
 *
 * Skipped on SQLite, where each process would have an in-memory database of its
 * own, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(FactorCodes::class)]
final class ConcurrentFactorCodesTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /** @var string The code the engine issues. */
    private const string CODE = '135790';

    /** @var string A code that is not the one issued. */
    private const string WRONG = '000000';

    /** @var string The table the counters record each report in, so it commits or rolls back with the check. */
    private const string REPORTS = 'factor_code_reports';

    /** @var int How long the first check holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second check must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second check waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second check reports its outcome in. */
    private string $outcomes;

    /** @var \Tests\Integration\Fixtures\CodeIdentity The identity the factor is the identity's. */
    private CodeIdentity $identity;

    /**
     * Skip where processes cannot share the database; freeze the clock so both
     * processes see one moment; create the tables and an identity; and bind
     * counters that admit every check and record each report in a table.
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

        CarbonImmutable::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE]);

        Schema::create(self::REPORTS, static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('challenge_id');
            $blueprint->boolean('passed');
        });

        $this->identity = self::seedCodeIdentity();

        $counters           = new RecordingFactorCodeCounters;
        $counters->observer = static function (string $call) use ($counters): void {
            if ($call !== 'report') {
                return;
            }

            [, $challengeId, $passed] = $counters->reports[count($counters->reports) - 1];

            DB::table(self::REPORTS)->insert(['challenge_id' => $challengeId, 'passed' => $passed]);
        };

        $this->app?->instance(FactorCodeCounters::class, $counters);

        Queue::fake();

        $this->outcomes = sys_get_temp_dir() . '/factor-code-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the tables and release the clock.
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

        Schema::dropIfExists(self::REPORTS);

        self::dropCodeIdentitiesTable();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Two wrong guesses at a challenge one attempt short of `max_attempts`: the
     * one whose transaction commits first counts the last attempt and is
     * `invalid`; the one admitted meanwhile waits on the challenge's row, then
     * finds it exhausted and counts nothing. The attempts stop at the maximum
     * and the counters were told of the one counted attempt once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoWrongGuessesAtTheLastAttemptCountItOnceAndReportItOnce(): void
    {
        $max       = config()->integer('authentication.codes.max_attempts');
        $challenge = (string) $this->codeService()->sendFactorCode($this->binding(), new ClientContext('203.0.113.7', 'Phone/1.0'))->challengeId;

        DB::table('one_time_codes')->update(['attempts' => $max - 1]);

        [$first, $second] = $this->race(
            fn (): string => $this->verify($challenge, '203.0.113.7'),
            fn (): string => $this->verify($challenge, '203.0.113.8'),
        );

        self::assertSame(FactorCodeOutcome::INVALID->value, $first);
        self::assertSame(FactorCodeOutcome::EXHAUSTED->value, $second['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame($max, self::storedAttempts());
        self::assertSame([[$challenge, false]], DB::table(self::REPORTS)->get()->map(static fn (object $report): array => [$report->challenge_id, (bool) $report->passed])->all());
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

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * The factor code binding for the identity's sign-in, on the `mobile`
     * application.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private function binding(): FactorCodeBinding
    {
        return new FactorCodeBinding(new ProofBinding($this->identity, 'mobile', 'session-1', Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::SMS, '+447700900555'));
    }

    /**
     * Check the wrong code for the challenge from the IP address, and answer
     * the outcome.
     *
     * @param  string  $challenge
     * @param  string  $ip
     * @return string
     *
     * @throws \Throwable
     */
    private function verify(string $challenge, string $ip): string
    {
        return $this->codeService()->verifyFactorCode($this->binding(), $challenge, self::WRONG, new ClientContext($ip, 'Phone/1.0'))->outcome->value;
    }

    /**
     * Run the first check here inside a transaction, start the second in
     * another process once the first has taken the challenge's row, hold the
     * transaction open while the second waits on it, then commit, and return
     * the first's outcome and the second's, with how long it waited.
     *
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @return array{0: string, 1: array{result: string, waited: float}}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $result = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $outcome = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($outcome);
        self::assertArrayNotHasKey('error', $outcome);

        /** @var array{result: string, waited: float} $outcome */
        return [$result, $outcome];
    }

    /**
     * In the forked process: wait to be started, run the check on a connection
     * of its own, report its outcome and how long it took, and end without
     * running the parent's shutdown.
     *
     * @param  \Closure(): string  $check
     * @return never
     */
    private function runInChild(\Closure $check): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = ['result' => $check(), 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
