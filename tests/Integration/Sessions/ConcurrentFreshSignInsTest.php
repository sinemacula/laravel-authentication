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
use SineMacula\Laravel\Authentication\Sessions\ConnectionGuards;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races fresh sign-ins of different identities, each in its own process, so
 * none waits on or deadlocks another.
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
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var int How long the first side waits for the second's proof insert to reach the server, in microseconds. */
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
     * Sign-ins of different identities neither wait nor deadlock.
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

        self::assertCount(3, array_unique(array_map(ConnectionGuards::slot(...), ['link-ada', 'link-grace', 'link-alan'])));

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

                return $this->startFor($grace, 'link-grace');
            });
        }

        DB::beginTransaction();

        $first = $this->startFor($ada, 'link-ada');

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/inserting")) {
            self::abandon($pid, 'The second side never reached the insert of its proof, so the sign-ins did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        $third = $this->startFor($alan, 'link-alan');

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
     * Start a new external session for the identity through the link and return
     * its key.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $linkId
     * @return string
     *
     * @throws \Throwable
     */
    private function startFor(IntegrationIdentity $identity, string $linkId): string
    {
        $session = $this->sessions()->signInExternally($this->linkedResult($identity, linkId: $linkId), self::requestContext())->session;

        self::assertNotNull($session);

        return (string) IdentifierCoercion::stringify($session->record->getKey());
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
     * second so neither holds locks. A failed fork's pid of `-1` would make
     * `posix_kill()` signal every process the user may.
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
