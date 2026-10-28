<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use Tests\Concerns\InteractsWithCodes;
use Tests\TestCase;

/**
 * Races one-time code operations on PostgreSQL and MySQL, each in a process
 * with a database connection of its own: one runs inside a transaction it holds
 * open, and the other, started meanwhile, waits on the code's row. Two checks
 * of the right code accept it once; a check racing a resend that drew the same
 * digits never accepts the code it read; two first issues for one binding
 * create one code.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodes::class)]
final class ConcurrentOneTimeCodesTest extends TestCase
{
    use InteractsWithCodes;

    /** @var string The code every issue draws. */
    private const string CODE = '424242';

    /** @var int How long the first operation holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second operation must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second operation waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var \Carbon\CarbonImmutable The moment both processes see. */
    private CarbonImmutable $now;

    /** @var string Directory the second operation reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, and freeze the clock so
     * both processes see one moment.
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

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);

        $this->outcomes = sys_get_temp_dir() . '/code-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes and release the clock.
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

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Of two checks of the right code, the one whose transaction commits first
     * accepts it; the one that waited on its row finds the code used and is
     * invalid.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoChecksOfTheRightCodeAcceptItOnce(): void
    {
        $this->issue($this->now);

        [$first, $second] = $this->race(
            fn (): string => self::codes()->check(self::binding(), self::CODE, $this->now)->value,
            fn (): string => self::codes()->check(self::binding(), self::CODE, $this->now)->value,
            commitFirst: true,
        );

        self::assertSame(CodeCheck::ACCEPTED->value, $first);
        self::assertSame(CodeCheck::INVALID->value, $second['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, self::attempts());
    }

    /**
     * When the first check's transaction rolls back, the check that waited on
     * its row accepts the code instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACheckWaitingOnOneThatRollsBackAcceptsTheCode(): void
    {
        $this->issue($this->now);

        [$first, $second] = $this->race(
            fn (): string => self::codes()->check(self::binding(), self::CODE, $this->now)->value,
            fn (): string => self::codes()->check(self::binding(), self::CODE, $this->now)->value,
            commitFirst: false,
        );

        self::assertSame(CodeCheck::ACCEPTED->value, $first);
        self::assertSame(CodeCheck::ACCEPTED->value, $second['result']);
        self::assertSame(1, self::attempts());
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A check of a code that a resend replaces, with the same digits, while the
     * check waits never accepts: it read the old issuance, so it cannot count
     * an attempt against it once the resend commits. The new issuance is
     * untouched and accepts the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACheckRacingAResendOfTheSameDigitsIsInvalid(): void
    {
        $this->issue($this->now);

        $later = $this->now->addSeconds(60);

        [$first, $second] = $this->race(
            fn (): string => $this->issue($later)->issueId,
            fn (): string => self::codes()->check(self::binding(), self::CODE, $later)->value,
            commitFirst: true,
        );

        self::assertSame($first, DB::table('one_time_codes')->value('issue_id'));
        self::assertSame(CodeCheck::INVALID->value, $second['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check(self::binding(), self::CODE, $later));
    }

    /**
     * Two first issues for one binding create one code: the one that waited on
     * the other's insert is told to wait out the cooldown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoFirstIssuesCreateOneCode(): void
    {
        [$first, $second] = $this->race(
            fn (): string => $this->issue($this->now)->issueId,
            fn (): int|string => self::outcomeOf(self::codes()->issue(self::binding(), $this->now)),
            commitFirst: true,
        );

        self::assertSame($first, DB::table('one_time_codes')->value('issue_id'));
        self::assertSame(60, $second['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, DB::table('one_time_codes')->count());
    }

    /**
     * When the first issue rolls back, the one that waited on its insert
     * creates the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIssueWaitingOnOneThatRollsBackCreatesTheCode(): void
    {
        [, $second] = $this->race(
            fn (): string => $this->issue($this->now)->issueId,
            fn (): int|string => self::outcomeOf(self::codes()->issue(self::binding(), $this->now)),
            commitFirst: false,
        );

        self::assertSame(DB::table('one_time_codes')->value('issue_id'), $second['result']);
        self::assertSame(1, DB::table('one_time_codes')->count());
    }

    /**
     * Run the first operation here inside a transaction, start the second in
     * another process, hold the transaction open while the second waits, then
     * commit or roll back, and return both outcomes.
     *
     * @param  \Closure(): (int|string)  $first
     * @param  \Closure(): (int|string)  $second
     * @param  bool  $commitFirst
     * @return array{0: int|string, 1: array{result: int|string, waited: float}}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, bool $commitFirst): array
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

        $commitFirst ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $outcome = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($outcome);
        self::assertArrayNotHasKey('error', $outcome);

        /** @var array{result: int|string, waited: float} $outcome */
        return [$result, $outcome];
    }

    /**
     * In the forked process: wait to be started, run the operation on a
     * connection of its own, report the outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): (int|string)  $operation
     * @return never
     */
    private function runInChild(\Closure $operation): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = ['result' => $operation(), 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The issuance an issue created, or the seconds it was told to wait.
     *
     * @param  int|\SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @return int|string
     */
    private static function outcomeOf(int|IssuedCode $issued): int|string
    {
        return $issued instanceof IssuedCode ? $issued->issueId : $issued;
    }

    /**
     * Issue the code for the binding at the time.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \Random\RandomException
     */
    private function issue(CarbonImmutable $at): IssuedCode
    {
        $issued = self::codes()->issue(self::binding(), $at);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued;
    }

    /**
     * An engine that always draws the same code.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodes
     */
    private static function codes(): OneTimeCodes
    {
        return self::sequence(array_fill(0, 3, self::CODE));
    }

    /**
     * The binding the codes are issued for.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeBinding
     */
    private static function binding(): CodeBinding
    {
        return CodeBinding::signIn('mobile', 'phone', '+447700900123');
    }

    /**
     * The attempts counted against the code.
     *
     * @return int
     */
    private static function attempts(): int
    {
        $attempts = DB::table('one_time_codes')->value('attempts');

        self::assertIsNumeric($attempts);

        return (int) $attempts;
    }
}
