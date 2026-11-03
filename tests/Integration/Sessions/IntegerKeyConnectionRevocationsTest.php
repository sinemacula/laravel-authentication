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
 * Integration tests of revocation by connection and by link over a session
 * model whose keys are integers the database issues, past one chunk: the
 * provenance holds the keys as strings, yet both triggers read and lock the
 * sessions in numeric order, and each session the connection established is
 * revoked exactly once. On PostgreSQL and MySQL a connection's revocation is
 * also raced, from a process with a database connection of its own, against a
 * transaction locking two of its sessions in key order across the chunk.
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
     * Freeze the clocks, create the tables and point the session model and its
     * table at the integer-keyed ones.
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
     * Drop the tables, put the session table back for the migrations' rollback
     * and release the clocks.
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
     * A disabled connection revokes every one of its integer-keyed sessions
     * once, across the chunk its string-ordered keys break at, and leaves
     * another connection's sessions alone.
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
     * A disabled connection reads its integer-keyed provenance a chunk at a
     * time: the first read names only the connection, and the next reads on
     * from the last key read before it, taking longer keys or ones as long that
     * sort after it.
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
     * A removed link revokes every one of the identity's integer-keyed sessions
     * established through it once, across the chunk its numerically ordered
     * keys break at, and leaves its other sessions alone; so does a widened
     * link scope.
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
     * Both triggers revoke, and so lock, the integer-keyed sessions in numeric
     * order across the chunk boundary, the order every other revocation locks
     * in: in string order the first chunk would hold 100 but not 99, and a
     * revocation holding 99 and waiting on 100 would deadlock with it.
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
     * A connection's revocation raced by a transaction that holds session 99
     * and then asks for 100, as a revocation locking in key order does, waits
     * on 99 and then revokes every session, and neither transaction deadlocks:
     * locking in string order, the revocation would already hold 100, from the
     * chunk before the one 99 falls in, when the other asked for it.
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
     * Insert the identity's live sessions under keys 1 to 504: those up to
     * `THROUGH` established through `conn-a`'s `link-1`, the rest through
     * `conn-b`'s.
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
     * In the forked process: in a transaction on a connection of its own, lock
     * session 99, signal that it is held, hold it, then lock session 100 and
     * commit; report the keys locked, or the error, and end without running the
     * parent's shutdown.
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
     * Wait for the other process to create the file, failing once the signal
     * timeout passes without it.
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
        return array_values(array_map(intval(...), DB::table(self::TABLE)->whereNull('revoked_at')->orderBy('id')->pluck('id')->all()));
    }
}
