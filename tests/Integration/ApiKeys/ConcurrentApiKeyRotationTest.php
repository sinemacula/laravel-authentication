<?php

declare(strict_types = 1);

namespace Tests\Integration\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Integration tests for API key rotations and revocations that race, each in a
 * process and on a connection of its own against a shared database server: the
 * second waits on the first's row lock and follows its outcome, so a key is
 * replaced once and revoked once, and each is reported once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyService::class)]
final class ConcurrentApiKeyRotationTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var int How long the first side holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second side must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second side waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Create the tables, freeze the clock and record the events, on a shared
     * database server only.
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

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->recordMachineEvents([ApiKeyRotated::class, ApiKeyRevoked::class]);

        $this->outcomes = sys_get_temp_dir() . '/api-key-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes and drop the tables.
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

        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * Two rotations of one key: the second waits on the first; once the first
     * commits it finds the key rotated and replaces nothing, and once the first
     * rolls back it rotates the key itself. Either way one replacement exists
     * and one rotation is reported.
     *
     * @return void
     */
    public function testTwoConcurrentRotationsReplaceTheKeyOnce(): void
    {
        foreach ([true, false] as $commit) {

            $machine = $this->seedMachine();
            $key     = $this->apiKeys()->issue($machine, $machine);

            [$first, $second] = $this->race(
                fn (): ?string => $this->apiKeys()->rotate($machine, $key->id, 60)?->id,
                fn (): ?string => $this->apiKeys()->rotate($machine, $key->id, 60)?->id,
                $commit,
            );

            self::assertNotNull($first);

            if ($commit) {
                self::assertNull($second['result']);
                self::assertSame([], $second['events']);
                self::assertCount(1, $this->machineEventsOf(ApiKeyRotated::class));
                self::assertSame($first, DB::table('api_keys')->where('id', $key->id)->value('replaced_by'));
            } else {
                self::assertIsString($second['result']);
                self::assertSame([ApiKeyRotated::class], $second['events']);
                self::assertSame([], $this->machineEvents);
                self::assertSame($second['result'], DB::table('api_keys')->where('id', $key->id)->value('replaced_by'));
            }

            self::assertSame(2, DB::table('api_keys')->count());
            self::assertSame('2026-04-06 12:01:00', DB::table('api_keys')->where('id', $key->id)->value('expires_at'));

            $this->reset();
        }
    }

    /**
     * Two revocations of one key: the second waits on the first and revokes
     * only when the first rolled back; the key is reported revoked once.
     *
     * @return void
     */
    public function testTwoConcurrentRevocationsReportTheKeyOnce(): void
    {
        foreach ([true, false] as $commit) {

            $machine = $this->seedMachine();
            $key     = $this->apiKeys()->issue($machine, $machine);

            [$first, $second] = $this->race(
                fn (): bool => $this->apiKeys()->revoke($machine, $key->id),
                fn (): bool => $this->apiKeys()->revoke($machine, $key->id),
                $commit,
            );

            self::assertTrue($first);
            self::assertSame(!$commit, $second['result']);
            self::assertSame($commit ? [] : [ApiKeyRevoked::class], $second['events']);
            self::assertCount($commit ? 1 : 0, $this->machineEventsOf(ApiKeyRevoked::class));
            self::assertNotNull(DB::table('api_keys')->where('id', $key->id)->value('revoked_at'));

            $this->reset();
        }
    }

    /**
     * A rotation waiting on a revocation of its key follows it: after a
     * committed revocation it replaces nothing, after a rolled back one it
     * rotates.
     *
     * @return void
     */
    public function testARotationWaitingOnARevocationFollowsIt(): void
    {
        foreach ([true, false] as $commit) {

            $machine = $this->seedMachine();
            $key     = $this->apiKeys()->issue($machine, $machine);

            [, $second] = $this->race(
                fn (): bool => $this->apiKeys()->revoke($machine, $key->id),
                fn (): ?string => $this->apiKeys()->rotate($machine, $key->id, 60)?->id,
                $commit,
            );

            if ($commit) {
                self::assertNull($second['result']);
                self::assertSame(1, DB::table('api_keys')->count());
            } else {
                self::assertIsString($second['result']);
                self::assertSame(2, DB::table('api_keys')->count());
            }

            $this->reset();
        }
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }

    /**
     * Run the first side inside a transaction in this process and the second in
     * a forked one, started once the first has written, then commit or roll
     * back the first: the first's result, and the second's result, events and
     * how long it waited.
     *
     * @param  \Closure(): mixed  $first
     * @param  \Closure(): mixed  $second
     * @param  bool  $commit
     * @return array{0: mixed, 1: array{result: mixed, events: list<class-string>, waited: float}}
     */
    private function race(\Closure $first, \Closure $second, bool $commit): array
    {
        $this->machineEvents = [];

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $outcome = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        $commit ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $reported['waited']);

        /** @var array{result: mixed, events: list<class-string>, waited: float} $reported */
        return [$outcome, $reported];
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
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $this->machineEvents = [];

            $started = microtime(true);
            $result  = $second();
            $events  = array_map(static fn (object $event): string => $event::class, $this->machineEvents);
            $outcome = ['result' => $result, 'events' => $events, 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Clear the rows and the outcome a race left, for the next one.
     *
     * @return void
     */
    private function reset(): void
    {
        DB::table('api_keys')->delete();

        MachineClient::query()->delete();

        unlink("{$this->outcomes}/start");
        unlink("{$this->outcomes}/outcome");
    }
}
