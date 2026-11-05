<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Sessions\SessionPruning;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\TestCase;

/**
 * Pruning against a refresh that extends a session's idle deadline on another
 * connection, on PostgreSQL and MySQL. Inside a caller's transaction that read
 * the session before the refresh committed, at READ COMMITTED and on MySQL at
 * REPEATABLE READ, each chunk's locking read judges the session on its current
 * row, so the refreshed session is kept with its proofs; a plain read would
 * return MySQL's snapshot and delete it by key. On PostgreSQL's REPEATABLE READ
 * no read sees past the snapshot, so the chunk fails to serialise instead and
 * deletes nothing. Outside a transaction, a refresh that arrives while a chunk
 * is under way waits for the chunk's lock.
 *
 * Skipped on SQLite, whose in-memory database each connection would have to
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPruning::class)]
final class ConcurrentSessionPruningTest extends TestCase
{
    use InteractsWithIsolationLevels;

    /** @var string The second connection to the test database, the one that refreshes. */
    private const string OTHER = 'other';

    /** @var string The frozen time every test prunes at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var ?bool Whether the refresh made during a chunk gave up waiting for its lock, once it was tried. */
    private ?bool $refreshWaited = null;

    /**
     * Skip where two connections cannot share the database, add the second
     * connection, freeze the clock and prune from the second a session ends.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Two connections need a shared database server.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, $config->get('database.connections.' . $config->string('database.default')));
        $config->set('authentication.session.prune_after_days', 0);

        Carbon::setTestNow(Carbon::parse(self::NOW));

        self::limitLockWaits('testing');
        self::limitLockWaits(self::OTHER);
    }

    /**
     * Close the second connection and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::OTHER);

        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A session whose idle deadline passed, read by the caller's transaction
     * and then refreshed and committed by another connection, is not pruned in
     * that transaction: it is kept with its proofs and provenance, or, where
     * the transaction reads a snapshot every read keeps, the chunk fails to
     * serialise and nothing is deleted.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testPruningInATransactionKeepsASessionRefreshedMeanwhile(string $level): void
    {
        $session = $this->insertSession(Carbon::parse(self::NOW)->subMinute());

        self::beginTransactionAt($level);

        self::assertSame(1, DB::table('authentication_sessions')->where('idle_expires_at', '<=', Carbon::parse(self::NOW))->count());

        $this->refreshElsewhere($session);

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::serializationFailure(static fn (): int => app(SessionPruning::class)->prune()));
        } else {
            self::assertSame(0, app(SessionPruning::class)->prune());

            DB::commit();
        }

        self::assertSame([$session], DB::table('authentication_sessions')->pluck('id')->all());
        self::assertSame([$session], DB::table('authentication_proofs')->pluck('session_id')->all());
        self::assertSame([$session], DB::table('authentication_provenance')->pluck('session_id')->all());
    }

    /**
     * Outside a transaction, a refresh that arrives once a chunk has read its
     * keys waits for the chunk to commit (here it gives up after the lock wait
     * limit), so it can never extend a session the chunk then deletes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshDuringAChunkWaitsForItsLock(): void
    {
        $session = $this->insertSession(Carbon::parse(self::NOW)->subMinute());

        DB::listen(function (QueryExecuted $query) use ($session): void {

            if ($this->refreshWaited !== null || !str_contains(strtolower($query->sql), 'for update')) {
                return;
            }

            try {
                $this->refreshElsewhere($session);

                $this->refreshWaited = false;
            } catch (QueryException) {
                $this->refreshWaited = true;
            }
        });

        self::assertSame(1, app(SessionPruning::class)->prune());
        self::assertTrue($this->refreshWaited);
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame(0, DB::table('authentication_proofs')->count());
    }

    /**
     * Extend the session's idle deadline by an hour on the other connection, as
     * a refresh does, and commit.
     *
     * @param  string  $session
     * @return void
     *
     * @throws \Illuminate\Database\QueryException
     */
    private function refreshElsewhere(string $session): void
    {
        DB::connection(self::OTHER)->table('authentication_sessions')->where('id', $session)->update([
            'idle_expires_at' => Carbon::parse(self::NOW)->addHour(),
        ]);
    }

    /**
     * Insert a session of the shipped table idle from the given time, with a
     * proof and a provenance, and return its key.
     *
     * @param  \Carbon\Carbon  $idle
     * @return string
     */
    private function insertSession(Carbon $idle): string
    {
        $id  = (string) Str::uuid7();
        $now = Carbon::parse(self::NOW);

        DB::table('authentication_sessions')->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'idle_expires_at'      => $idle,
            'absolute_expires_at'  => $now->copy()->addDays(30),
            'signed_in_at'         => $now->copy()->subDay(),
            'created_at'           => $now->copy()->subDay(),
            'updated_at'           => $now->copy()->subDay(),
        ]);

        DB::table('authentication_proofs')->insert([
            'id'                   => (string) Str::uuid7(),
            'session_id'           => $id,
            'kind'                 => 'first_factor',
            'purpose'              => 'sign_in',
            'method'               => 'password',
            'channel_kind'         => 'password',
            'methods'              => '["pwd"]',
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'authenticated_at'     => $now->copy()->subDay(),
            'created_at'           => $now->copy()->subDay(),
        ]);

        DB::table('authentication_provenance')->insert(['session_id' => $id, 'connection_id' => 'connection-7', 'created_at' => $now->copy()->subDay()]);

        return $id;
    }
}
