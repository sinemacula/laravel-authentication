<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegerKeySession;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests of revocation by connection and by link over integer
 * session keys, past one chunk.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
final class IntegerKeyConnectionRevocationsTest extends TestCase
{
    use InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The integer-keyed session table the sessions live in. */
    private const string TABLE = 'integer_key_sessions';

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var int How many sessions the connection established: one past a chunk, so string and numeric order differ across it. */
    private const int THROUGH = ConnectionRevocations::CHUNK + 1;

    /** @var int How long the racing transaction holds the first session it locks before asking for the next, in microseconds. */
    private const int HOLD_MICROSECONDS = 2000000;

    /** @var int How long either process waits on the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /**
     * Freeze the clocks, create the tables and point the session model at the
     * integer-keyed ones.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        self::createSessionRecordTable(self::TABLE, incrementing: true);

        config()->set('authentication.session.model', IntegerKeySession::class);
        config()->set('authentication.session.table', self::TABLE);
    }

    /**
     * Drop the tables, restore the session table and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('authentication.session.table', 'authentication_sessions');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A disabled connection revokes each of its integer-keyed sessions once,
     * across the chunk.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryIntegerKeyedSessionOfTheConnectionIsRevokedOnce(): void
    {
        $this->insertSessions($this->seedIdentity());

        self::assertSame(self::THROUGH, Auth::sessions('api')->connectionDisabled('conn-a'));
        self::assertSame(self::THROUGH, DB::table(self::TABLE)->where('revoked_reason', 'connection_disabled')->count());
        self::assertSame([502, 503, 504], self::unrevoked());
        self::assertSame(0, Auth::sessions('api')->connectionDisabled('conn-a'));
    }

    /**
     * A disabled connection reads its provenance a chunk at a time, on from the
     * last key read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachChunkReadsOnFromTheLastKeyRead(): void
    {
        $this->insertSessions($this->seedIdentity());

        $reads = [];

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            if (!str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'authentication_provenance')) {
                return;
            }

            $reads[] = $query->bindings;
        });

        Auth::sessions('api')->connectionDisabled('conn-a');

        self::assertSame([['conn-a'], ['conn-a', 3, 3, '500']], $reads);
    }

    /**
     * A removed or widened link revokes each integer-keyed session it
     * established once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryIntegerKeyedSessionThroughTheLinkIsRevokedOnce(): void
    {
        $identity = $this->seedIdentity();

        $this->insertSessions($identity);

        self::assertSame(self::THROUGH, Auth::sessions('api')->linkRemoved($identity, 'conn-a', 'link-1'));
        self::assertSame(self::THROUGH, DB::table(self::TABLE)->where('revoked_reason', 'link_removed')->count());
        self::assertSame([502, 503, 504], self::unrevoked());
        self::assertSame(0, Auth::sessions('api')->linkRemoved($identity, 'conn-a', 'link-1'));

        DB::table(self::TABLE)->update(['revoked_at' => null, 'revoked_reason' => null]);

        self::assertSame(self::THROUGH, Auth::sessions('api')->linkScopeWidened($identity, 'conn-a', 'link-1'));
        self::assertSame([502, 503, 504], self::unrevoked());
    }

    /**
     * Both triggers lock sessions in numeric key order across the chunk, the
     * order every other revocation locks in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBothTriggersRevokeInNumericKeyOrderAcrossTheChunk(): void
    {
        $identity = $this->seedIdentity();

        /** @var \ArrayObject<int, int> $revoked */
        $revoked = new \ArrayObject;

        $this->insertSessions($identity);

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use ($revoked): void {
            $revoked->append((int) $event->context->sessionId);
        });

        self::assertSame(self::THROUGH, Auth::sessions('api')->connectionDisabled('conn-a'));
        self::assertSame(range(1, self::THROUGH), $revoked->getArrayCopy());

        DB::table(self::TABLE)->update(['revoked_at' => null, 'revoked_reason' => null]);

        $revoked->exchangeArray([]);

        self::assertSame(self::THROUGH, Auth::sessions('api')->linkRemoved($identity, 'conn-a', 'link-1'));
        self::assertSame(range(1, self::THROUGH), $revoked->getArrayCopy());
    }

    /**
     * A connection's revocation never deadlocks with a transaction that locks
     * in key order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConnectionsRevocationNeverDeadlocksWithAnotherLockingInKeyOrder(): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->insertSessions($this->seedIdentity());

        $signals = sys_get_temp_dir() . '/connection-revocation-race-' . bin2hex(random_bytes(8));

        mkdir($signals);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            self::lockInKeyOrderInChild($signals);
        }

        try {
            self::waitFor("{$signals}/held");

            $revoked = Auth::sessions('api')->connectionDisabled('conn-a');
        } finally {
            pcntl_waitpid($pid, $status);
        }

        $reported = json_decode((string) file_get_contents("{$signals}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        array_map(unlink(...), glob("{$signals}/*") ?: []);
        rmdir($signals);

        self::assertSame(['locked' => [99, 100]], $reported);
        self::assertSame(self::THROUGH, $revoked);
        self::assertSame(self::THROUGH, DB::table(self::TABLE)->where('revoked_reason', 'connection_disabled')->count());
    }

    /**
     * Register the session guards.
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
     * Insert the identity's sessions under keys 1 to 504, split between
     * `conn-a` and `conn-b`.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return void
     */
    private function insertSessions(IntegrationIdentity $identity): void
    {
        $owner    = IdentifierCoercion::stringify($identity->getKey());
        $sessions = array_map(static fn (int $key): array => [
            'id'                   => $key,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => $owner,
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => $owner,
            'status'               => 'active',
            'guard'                => 'api',
            'sign_in_method'       => 'external_provider',
            'refresh_key'          => hash('sha256', 'refresh-' . $key),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ], range(1, self::THROUGH + 3));

        $provenance = array_map(static fn (int $key): array => [
            'session_id'    => (string) $key,
            'connection_id' => $key <= self::THROUGH ? 'conn-a' : 'conn-b',
            'link_id'       => 'link-1',
            'created_at'    => self::NOW,
        ], range(1, self::THROUGH + 3));

        foreach (array_chunk($sessions, 200) as $chunk) {
            DB::table(self::TABLE)->insert($chunk);
        }

        foreach (array_chunk($provenance, 200) as $chunk) {
            DB::table('authentication_provenance')->insert($chunk);
        }
    }

    /**
     * In the forked process, lock sessions 99 then 100 on its own connection
     * and report the keys locked.
     *
     * @param  string  $signals
     * @return never
     */
    private static function lockInKeyOrderInChild(string $signals): never
    {
        try {
            DB::transaction(static function () use ($signals): void {

                DB::table(self::TABLE)->where('id', 99)->lockForUpdate()->first();

                touch("{$signals}/held");
                usleep(self::HOLD_MICROSECONDS);

                DB::table(self::TABLE)->where('id', 100)->lockForUpdate()->first();
            });

            $outcome = ['locked' => [99, 100]];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$signals}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait for the other process to create the file, failing after the signal
     * timeout.
     *
     * @param  string  $file
     * @return void
     */
    private static function waitFor(string $file): void
    {
        $deadline = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        while (!is_file($file)) {
            if (microtime(true) >= $deadline) {
                self::fail("The racing process never signalled {$file}.");
            }

            usleep(5000);
        }
    }

    /**
     * The keys of the sessions left unrevoked, in order.
     *
     * @return list<int>
     */
    private static function unrevoked(): array
    {
        return array_values(array_map(self::storedInt(...), DB::table(self::TABLE)->whereNull('revoked_at')->orderBy('id')->pluck('id')->all()));
    }
}
