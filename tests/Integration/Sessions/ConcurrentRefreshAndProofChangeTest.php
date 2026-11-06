<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races a refresh against a change of its session's proofs on PostgreSQL and
 * MySQL, each side in a process with a database connection of its own: the
 * first side changes the proofs (a step-up that adds `hwk` and `mfa`, or the
 * removal of the factor a step-up was made with) inside a transaction it holds
 * open; the second side refreshes the session meanwhile, starting a second
 * before the step-up's proof. The refresh writes the session's issuance guard
 * before anything else it reads, so it waits on the first side's lock of the
 * row, takes its time once the first side has committed, and then reads the
 * proofs as committed: its token carries the step-up's `auth_time` and values,
 * not the second it started in, and never the removed factor's values. A
 * refresh that read the proofs before it waited (only its compare-and-swap
 * waiting) would have handed out a token older than the step-up's, or one that
 * still counts the removed factor; one that took its time before the guard
 * would carry the second it started in. On MySQL the shared lock of the current
 * read waits on the first side's uncommitted proof rows too; on PostgreSQL only
 * the guard makes the refresh wait.
 *
 * Under PostgreSQL's REPEATABLE READ the refresh's transaction takes its
 * snapshot at the guard, before it waits, so the guard fails to serialise once
 * the first side commits, and the refresh retried carries the step-up's
 * authentication; under MySQL's it waits and reads current, as at READ
 * COMMITTED.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuanceGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(ProofIssuance::class)]
#[CoversClass(FactorRevocations::class)]
final class ConcurrentRefreshAndProofChangeTest extends TestCase
{
    use InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var int How long the first side holds its transaction once the second waits on the guard, in microseconds. */
    private const int SETTLE_MICROSECONDS = 300000;

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var \Carbon\CarbonImmutable The second the refresh starts in, an hour after the sign-in. */
    private CarbonImmutable $refreshedAt;

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

        $this->refreshedAt = CarbonImmutable::createStrict(2026, 4, 6, 13, 0, 0);

        $this->freezeAt($this->refreshedAt->subHour());

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/refresh-proof-race-' . bin2hex(random_bytes(8));

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
     * A refresh that starts while a step-up holds the session's row waits for
     * it, and its token carries the step-up's `auth_time`, a second after the
     * refresh started, and its `hwk` and `mfa`; under PostgreSQL's REPEATABLE
     * READ it fails to serialise first and carries them once retried.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefreshThatWaitsOnAStepUpCarriesItsAuthentication(string $level): void
    {
        $signedIn    = $this->signedIn();
        $steppedUpAt = $this->refreshedAt->addSecond();

        $reported = $this->race(
            $level,
            function () use ($signedIn, $steppedUpAt): void {
                $this->freezeAt($steppedUpAt);

                $proof = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), methods: ['hwk'], evaluation: new Evaluation(true, true));

                self::assertTrue($this->sessions()->stepUp($proof, self::requestClient())->isIssued());
            },
            $signedIn,
            $steppedUpAt,
        );

        self::assertSame(self::readsASnapshot($level) ? '40001' : null, $reported['failed']);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);
        self::assertSame($steppedUpAt->getTimestamp(), $reported['claims']['iat']);
        self::assertSame($steppedUpAt->getTimestamp(), $reported['claims']['auth_time']);
        self::assertContains('hwk', $reported['claims']['amr']);
        self::assertContains('mfa', $reported['claims']['amr']);
    }

    /**
     * A refresh that starts while the removal of a factor holds the session's
     * row waits for it, and its token never counts the factor removed: the
     * step-up made with it no longer adds `hwk` or `mfa`, and the time is the
     * sign-in's again; under PostgreSQL's REPEATABLE READ it fails to serialise
     * first, and the refresh retried still never counts the factor.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefreshThatWaitsOnAFactorRemovalNeverCountsTheFactor(string $level): void
    {
        $signedIn = $this->signedIn();
        $proof    = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), methods: ['hwk'], evaluation: new Evaluation(true, true));

        self::assertTrue($this->sessions()->stepUp($proof, self::requestClient())->isIssued());

        $reported = $this->race(
            $level,
            function () use ($signedIn): void {
                self::assertFalse(Auth::sessions('api')->factorRemoved($signedIn->identity, 'factor-1', $signedIn->record)->isPending());
            },
            $signedIn,
            $this->refreshedAt,
        );

        self::assertSame(self::readsASnapshot($level) ? '40001' : null, $reported['failed']);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);
        self::assertSame($this->refreshedAt->subHour()->getTimestamp(), $reported['claims']['auth_time']);
        self::assertSame(['pwd'], $reported['claims']['amr']);
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
     * A session the seeded identity signed in to with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $signedIn = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($signedIn);

        return $signedIn;
    }

    /**
     * Change the session's proofs here inside a transaction, start the refresh
     * in another process at `refreshedAt`, hold the transaction open until the
     * refresh is about to write the session's issuance guard and a little
     * longer, then commit, and return what the refresh reported: whether it
     * failed to serialise first, how long it took, and its access token's
     * claims. The refresh's clock moves to `$resumesAt` once its guard is
     * written, as time passes while it waits.
     *
     * @param  string  $level
     * @param  \Closure(): void  $change
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @param  \Carbon\CarbonImmutable  $resumesAt
     * @return array{failed: ?string, waited: float, claims: array<string, mixed>}
     *
     * @throws \Throwable
     */
    private function race(string $level, \Closure $change, SignedInSession $signedIn, CarbonImmutable $resumesAt): array
    {
        $refreshToken = (string) $signedIn->tokens->refreshToken?->reveal();

        $this->freezeAt($this->refreshedAt);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(fn (): array => $this->refreshAt($level, $refreshToken, $resumesAt));
        }

        DB::beginTransaction();

        $change();

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/guarding")) {
            self::abandon($pid, 'The refresh never reached its issuance guard, so the two did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);

        /** @var array{failed: ?string, waited: float, claims: array<string, mixed>} $reported */
        return $reported;
    }

    /**
     * In the forked process: refresh at the isolation level, signalling just
     * before the issuance guard is sent and moving the clock once it has been
     * written, retry once after a failure to serialise, and return the access
     * token's claims.
     *
     * @param  string  $level
     * @param  string  $refreshToken
     * @param  \Carbon\CarbonImmutable  $resumesAt
     * @return array{failed: ?string, claims: mixed}
     *
     * @throws \Throwable
     */
    private function refreshAt(string $level, #[\SensitiveParameter] string $refreshToken, CarbonImmutable $resumesAt): array
    {
        $connection = DB::connection();

        $connection->statement(match ($connection->getDriverName()) {
            'mysql' => 'set session transaction isolation level ' . $level,
            default => 'set session characteristics as transaction isolation level ' . $level,
        });

        $connection->beforeExecuting(function (string $query): void {
            if (!str_contains($query, 'issuance_sequence')) {
                return;
            }

            touch("{$this->outcomes}/guarding");
        });

        DB::listen(function (QueryExecuted $query) use ($resumesAt): void {
            if (!str_contains($query->sql, 'issuance_sequence')) {
                return;
            }

            $this->freezeAt($resumesAt);
        });

        $failed = null;

        try {
            $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient());
        } catch (QueryException $exception) {
            $failed    = (string) $exception->getPrevious()?->getCode();
            $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient());
        }

        $claims = Auth::manager()->jwt('api')->parse((string) $refreshed->session?->tokens->accessToken->reveal(), TokenType::ACCESS);

        return ['failed' => $failed, 'claims' => $claims];
    }

    /**
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): array<string, mixed>  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        $outcome = ['error' => 'The first side never signalled the start.'];

        try {
            if (self::wasSignalled("{$this->outcomes}/start")) {
                $started = microtime(true);
                $outcome = [...$second(), 'waited' => microtime(true) - $started];
            }
        } catch (\Throwable $e) {
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
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
