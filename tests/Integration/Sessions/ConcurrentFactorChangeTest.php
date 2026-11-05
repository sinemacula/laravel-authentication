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
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races the factor-change gate against a revocation of the session it is asked
 * about, and against a factor's removal that voids the step-up it would count,
 * on PostgreSQL and MySQL, each in a process with a database connection of its
 * own: the gate's lock on the session's row is held until the caller's
 * transaction commits, so a revocation started meanwhile waits for the change,
 * a gate started while a revocation holds the row waits and then finds the
 * session revoked, and a gate started while a removal holds it waits and then
 * judges the session's proofs as committed, whatever its caller's transaction
 * read first.
 *
 * Skipped on SQLite, where each process would have an in-memory database of its
 * own, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGate::class)]
final class ConcurrentFactorChangeTest extends TestCase
{
    use InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var int How long the first call holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second call must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second call waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second call reports its outcome in. */
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

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/factor-change-race-' . bin2hex(random_bytes(8));

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
     * A revocation that waits on a change the gate allowed finds the change
     * committed first, then revokes the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationWaitsOnAnAllowedChange(): void
    {
        $signedIn = $this->steppedUp();
        $key      = $signedIn->record->getKey();

        [$allowed, $second] = $this->race(
            fn (): bool => $this->sessions()->factorChange($signedIn->record, FactorChange::ADD)->isAllowed(),
            fn (): array => ['revoked' => $this->sessions()->revokeSession($signedIn->identity, $key, RevocationReason::SIGNED_OUT)],
        );

        self::assertTrue($allowed);
        self::assertTrue($second['revoked']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(RevocationReason::SIGNED_OUT->value, Session::query()->sole()->revoked_reason);
    }

    /**
     * A change asked while a revocation holds the session's row waits on it,
     * then finds the session revoked and is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeWaitingOnARevocationIsRefused(): void
    {
        $signedIn = $this->steppedUp();
        $key      = $signedIn->record->getKey();

        [$revoked, $second] = $this->race(
            fn (): bool => $this->sessions()->revokeSession($signedIn->identity, $key, RevocationReason::SIGNED_OUT),
            fn (): array => ['reason' => $this->sessions()->factorChange($signedIn->record, FactorChange::ADD)->reason?->value],
        );

        self::assertTrue($revoked);
        self::assertSame(FailureReason::SESSION_REVOKED->value, $second['reason']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A change asked inside a caller's transaction that read the session's
     * proofs first, while a removal of the step-up's factor on another
     * connection holds the session's row, waits on it, then never counts the
     * step-up the removal voided: it is refused (`step_up_required`) with no
     * proof. At PostgreSQL's REPEATABLE READ the gate's lock fails to serialise
     * first, and the caller's retry of its whole transaction is refused the
     * same way. A gate that judged the caller's snapshot would allow the change
     * on a proof that no longer counts.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAChangeWaitingOnAFactorRemovalNeverCountsTheStepUpItVoided(string $level): void
    {
        $signedIn = $this->steppedUp();
        $snapshot = self::readsASnapshot($level);

        [$removal, $second] = $this->race(
            function () use ($signedIn): array {
                $removal = $this->sessions()->factorRemoved($signedIn->identity, 'factor-1', $signedIn->record);

                return [$removal->revoked, $removal->currentRevoked, $removal->isPending()];
            },
            function () use ($level, $signedIn, $snapshot): array {
                $change  = fn (): FactorChangeVerdict => $this->sessions()->factorChange($signedIn->record, FactorChange::ADD);
                $failure = $snapshot ? self::serializationFailure($change) : null;

                if ($snapshot) {
                    self::beginTransactionAt($level);
                }

                $verdict = $change();

                DB::commit();

                return ['failure' => $failure, 'reason' => $verdict->reason?->value, 'proof' => $verdict->proof?->id];
            },
            static function () use ($level): void {
                self::beginTransactionAt($level);

                self::assertSame(0, DB::table('authentication_proofs')->whereNotNull('voided_at')->count());
            },
        );

        self::assertSame([0, false, false], $removal);
        self::assertSame([$snapshot ? '40001' : null, FailureReason::STEP_UP_REQUIRED->value, null], [$second['failure'], $second['reason'], $second['proof']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, DB::table('authentication_proofs')->whereNotNull('voided_at')->count());
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
     * Sign the seeded identity in and step its session up with a further
     * factor, so the gate allows changing one from it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function steppedUp(): SignedInSession
    {
        $this->seedIdentity();

        $signedIn = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($signedIn);
        self::assertTrue($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), Purpose::STEP_UP))->isIssued());

        return $signedIn;
    }

    /**
     * Run the first call here inside a transaction, start the second in another
     * process once the first has taken its locks, hold the transaction open
     * while the second waits on them, then commit, and return the first's
     * outcome and the second's, with how long it waited. Work to prepare the
     * second, given, runs in the other process before the first starts (a
     * caller's transaction opened and read first, say).
     *
     * @param  \Closure(): mixed  $first
     * @param  \Closure(): array<string, mixed>  $second
     * @param  ?\Closure(): void  $prepare
     * @return array{0: mixed, 1: array<array-key, mixed>}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, ?\Closure $prepare = null): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second, $prepare);
        }

        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while ($prepare !== null && !is_file("{$this->outcomes}/prepared") && !is_file("{$this->outcomes}/outcome") && microtime(true) < $deadline) {
            usleep(5000);
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
     * In the forked process: run the preparation, if any, and say so, wait to
     * be started, run the call on a connection of its own, report its outcome
     * and how long it took, and end without running the parent's shutdown.
     *
     * @param  \Closure(): array<string, mixed>  $call
     * @param  ?\Closure(): void  $prepare
     * @return never
     */
    private function runInChild(\Closure $call, ?\Closure $prepare): never
    {
        try {
            if ($prepare !== null) {
                $prepare();

                touch("{$this->outcomes}/prepared");
            }

            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = [...$call(), 'waited' => 0.0];

            $outcome['waited'] = microtime(true) - $started;
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
