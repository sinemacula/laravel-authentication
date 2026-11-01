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
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races sign-ins of different identities that each start a new session, on
 * PostgreSQL and MySQL, each side in a process with a database connection of
 * its own: one side signs in inside a transaction it holds open, the other,
 * started meanwhile, signs in, and the first, once the other has reached the
 * insert of its proof, signs in again before it commits. A new session's key
 * sorts after every key already recorded, so the sign-ins all write their
 * proofs and provenance at the end of the same indexes; clearing what an
 * earlier session left under a key must lock nothing there, or on MySQL the
 * second side waits on the first and the first's next sign-in then waits on the
 * second, a deadlock that fails one of them. Neither side waits, and every
 * sign-in commits with its own proof and provenance.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofWriter::class)]
#[CoversClass(SessionWriter::class)]
final class ConcurrentFreshSignInsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var int How long the first side waits, once the second is about to insert its proof, for that insert to reach the server, in microseconds. */
    private const int SETTLE_MICROSECONDS = 200000;

    /** @var float The most time, in seconds, the second side may take, to show it never waited on the first. */
    private const float MOST_WAIT_SECONDS = 0.5;

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var list<class-string> The events both sides record. */
    private const array EVENTS = [SessionCreated::class, SignedIn::class];

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

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/fresh-sign-in-race-' . bin2hex(random_bytes(8));

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
     * A sign-in of another identity, while the first side holds its sign-in
     * open, does not wait on it, and the first side's next sign-in, made once
     * the second has sent the insert of its proof (where it would be waiting if
     * it had to), does not wait on the second's: all three commit, each session
     * with only its own first factor and provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInsOfDifferentIdentitiesNeitherWaitNorDeadlock(): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');
        $alan  = $this->seedIdentity('alan@example.test');

        $this->recordEvents(self::EVENTS);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($grace): string {
                $inserting = "{$this->outcomes}/inserting";

                SessionProof::creating(static function () use ($inserting): void {
                    touch($inserting);
                });

                return $this->startFor($grace);
            });
        }

        DB::beginTransaction();

        $first = $this->startFor($ada);

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/inserting")) {
            self::abandon($pid, 'The second side never reached the insert of its proof, so the sign-ins did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        $third = $this->startFor($alan);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertLessThan(self::MOST_WAIT_SECONDS, $reported['waited']);
        self::assertSame([SessionCreated::class, SignedIn::class], $reported['events']);
        self::assertSame([SessionCreated::class, SignedIn::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertIsString($reported['result']);

        $keys = [$first, $reported['result'], $third];

        self::assertSame(3, DB::table('authentication_sessions')->whereIn('id', $keys)->whereNull('revoked_at')->count());
        self::assertSame(3, DB::table('authentication_proofs')->count());
        self::assertSame(3, DB::table('authentication_provenance')->count());

        foreach ($keys as $key) {
            self::assertSame(['first_factor'], DB::table('authentication_proofs')->where('session_id', $key)->pluck('kind')->all());
            self::assertTrue(DB::table('authentication_provenance')->where('session_id', $key)->exists());
        }
    }

    /**
     * Register the guards.
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
     * Start a new session for the identity, as an external provider established
     * it, and return its key. `start()` takes no attempt-limit slot, so the
     * sides share no row.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function startFor(IntegrationIdentity $identity): string
    {
        $session = $this->sessions()->start($identity, null, 'sso', null, new Provenance('connection-7'))->session;

        self::assertNotNull($session);

        return (string) IdentifierCoercion::stringify($session->record->getKey());
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
                $outcome = ['result' => $result, 'events' => $this->recordedClasses(), 'waited' => microtime(true) - $started];
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
     * on the tables the teardown drops. The pid is the forked child's, never a
     * failed fork's `-1`, which `posix_kill()` would send to every process the
     * user may signal.
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
