<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SessionPruning;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\SoftDeletingPruningSession;
use Tests\TestCase;

/**
 * Feature tests for `SessionPruning` on a read/write split connection whose
 * replica lags behind the primary: the cutoff it reads, the query it selects
 * and counts by, the chunks it deletes with their proofs and provenance, what
 * it reports after each, how it fails, and that it reads from the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPruning::class)]
#[CoversClass(SessionRetention::class)]
final class SessionPruningTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string The frozen time every test prunes at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var string The cutoff for the default 30 days of retention. */
    private const string CUTOFF = '2026-12-16 10:00:00';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse(self::NOW));
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * The count reads the primary: sessions written moments ago, which the
     * replica does not hold yet, are counted.
     *
     * @return void
     */
    public function testCountReadsTheWriteConnection(): void
    {
        $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));
        $this->insertSession(idle: Carbon::parse(self::CUTOFF));
        $this->insertSession();

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->count());
        self::assertSame(2, app(SessionPruning::class)->count());
        self::assertSame(3, self::rows('authentication_sessions')->count());
    }

    /**
     * The count and each chunk's key read select sessions revoked, idle-expired
     * or absolutely expired at or before now less the retention, a whole
     * second, with the conditions grouped; a chunk reads its keys in key order,
     * a chunk at most.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheQueriesCutOffAtNowLessTheRetention(): void
    {
        Carbon::setTestNow(Carbon::parse('2027-01-15 10:00:00.750'));

        $cutoff = ['2026-12-16 10:00:00', '2026-12-16 10:00:00', '2026-12-16 10:00:00'];
        $where  = 'where (revoked_at <= ? or idle_expires_at <= ? or absolute_expires_at <= ?)';

        $queries = $this->queriesOf(static fn (): int => app(SessionPruning::class)->count());

        self::assertSame([['select count(*) as aggregate from authentication_sessions ' . $where, $cutoff]], $queries);

        $queries = $this->queriesOf(static fn (): int => app(SessionPruning::class)->prune(25));

        self::assertSame([['select id from authentication_sessions ' . $where . ' order by authentication_sessions.id asc limit 25', $cutoff]], $queries);
    }

    /**
     * Retentions that are accepted, with the cutoff each gives at 2027-01-15
     * 10:00:00.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function acceptedRetentions(): iterable
    {
        yield 'zero' => [0, '2027-01-15 10:00:00'];
        yield 'zero as a string' => ['0', '2027-01-15 10:00:00'];
        yield 'one' => [1, '2027-01-14 10:00:00'];
        yield 'a digit string' => ['7', '2027-01-08 10:00:00'];
        yield 'four digits' => ['3650', '2017-01-17 10:00:00'];
        yield 'the maximum' => [3650, '2017-01-17 10:00:00'];
    }

    /**
     * Each accepted retention moves the cutoff back that many days.
     *
     * @param  int|string  $days
     * @param  string  $cutoff
     * @return void
     */
    #[DataProvider('acceptedRetentions')]
    public function testAcceptsIntegersAndDigitStringsFromZeroToTenYears(int|string $days, string $cutoff): void
    {
        config()->set('authentication.session.prune_after_days', $days);

        $queries = $this->queriesOf(static fn (): int => app(SessionPruning::class)->count());

        self::assertSame([$cutoff, $cutoff, $cutoff], $queries[0][1]);
    }

    /**
     * Retentions that are refused.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function rejectedRetentions(): iterable
    {
        yield 'negative' => [-1];
        yield 'over ten years' => [3651];
        yield 'over ten years as a string' => ['3651'];
        yield 'five digits' => ['10000'];
        yield 'padded' => ['030'];
        yield 'signed' => ['+7'];
        yield 'negative string' => ['-1'];
        yield 'fraction string' => ['1.5'];
        yield 'float' => [1.5];
        yield 'trailing newline' => ["7\n"];
        yield 'empty' => [''];
        yield 'words' => ['thirty'];
        yield 'null' => [null];
        yield 'boolean' => [true];
        yield 'array' => [[30]];
    }

    /**
     * Any other retention fails closed, before anything is read, when the
     * sessions are counted and when they are pruned.
     *
     * @param  mixed  $days
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('rejectedRetentions')]
    public function testRejectsAnyOtherRetentionBeforeAnyQuery(mixed $days): void
    {
        $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));

        config()->set('authentication.session.prune_after_days', $days);

        foreach ([static fn (): int => app(SessionPruning::class)->count(), static fn (): int => app(SessionPruning::class)->prune()] as $call) {
            self::assertSame([], $this->queriesOf(static function () use ($call): void {
                try {
                    $call();

                    self::fail('The retention was accepted.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame('authentication.session.prune_after_days must be an integer from 0 to 3650.', $exception->getMessage());
                }
            }));
        }

        self::assertSame(1, self::rows('authentication_sessions')->count());
    }

    /**
     * Chunk sizes below 1.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function refusedChunkSizes(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    /**
     * A chunk size below 1 is refused before anything is read.
     *
     * @param  int  $chunkSize
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('refusedChunkSizes')]
    public function testRefusesAChunkSizeBelowOneBeforeAnyQuery(int $chunkSize): void
    {
        $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));

        self::assertSame([], $this->queriesOf(static function () use ($chunkSize): void {
            try {
                app(SessionPruning::class)->prune($chunkSize);

                self::fail('The chunk size was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The chunk size must be at least 1.', $exception->getMessage());
            }
        }));

        self::assertSame(1, self::rows('authentication_sessions')->count());
    }

    /**
     * A session model configuration that is not valid fails before anything is
     * read, when the sessions are counted and when they are pruned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidSessionModelFailsBeforeAnyQuery(): void
    {
        config()->set('authentication.session.model', \stdClass::class);

        foreach ([static fn (): int => app(SessionPruning::class)->count(), static fn (): int => app(SessionPruning::class)->prune()] as $call) {
            self::assertSame([], $this->queriesOf(static function () use ($call): void {
                try {
                    $call();

                    self::fail('The session model was accepted.');
                } catch (InvalidSessionModelConfigurationException) {
                    self::assertTrue(true);
                }
            }));
        }
    }

    /**
     * Sessions are pruned a chunk at a time with their proofs and provenance,
     * and after each chunk `ModelsPruned` names the session model with the
     * running total, which the callback receives too; the sessions kept keep
     * their own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrunesInChunksAndReportsEachChunk(): void
    {
        $pruned = [];

        for ($index = 0; $index < 5; $index++) {
            $this->insertProofsOf($pruned[] = $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF)));
        }

        $this->insertProofsOf($live = $this->insertSession());

        Event::fake([ModelsPruned::class]);

        $totals = [];
        $total  = app(SessionPruning::class)->prune(2, static function (int $total) use (&$totals): void {
            $totals[] = $total;
        });

        self::assertSame(5, $total);
        self::assertSame([2, 4, 5], $totals);
        self::assertSame([$live], self::rows('authentication_sessions')->pluck('id')->all());
        self::assertSame([$live, $live], self::rows('authentication_proofs')->pluck('session_id')->all());
        self::assertSame([$live], self::rows('authentication_provenance')->pluck('session_id')->all());

        $events = array_map(static fn (array $dispatched): array => [$dispatched[0]->model, $dispatched[0]->count], Event::dispatched(ModelsPruned::class)->all());

        self::assertSame([[Session::class, 2], [Session::class, 4], [Session::class, 5]], $events);
    }

    /**
     * By default a chunk is 1,000 sessions, and a chunk of 1 prunes one session
     * at a time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChunksAreAThousandSessionsByDefaultAndOneAtLeast(): void
    {
        $rows = [];

        for ($index = 0; $index < 1001; $index++) {
            $rows[] = $this->sessionRow(revokedAt: Carbon::parse(self::CUTOFF));
        }

        foreach (array_chunk($rows, 250) as $chunk) {
            self::rows('authentication_sessions')->insert($chunk);
        }

        $totals = [];

        self::assertSame(1001, app(SessionPruning::class)->prune(pruned: static function (int $total) use (&$totals): void {
            $totals[] = $total;
        }));
        self::assertSame([1000, 1001], $totals);

        $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));
        $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));

        $totals = [];

        self::assertSame(2, app(SessionPruning::class)->prune(1, static function (int $total) use (&$totals): void {
            $totals[] = $total;
        }));
        self::assertSame([1, 2], $totals);
    }

    /**
     * With nothing to prune, nothing is reported and nothing is deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingToPruneReportsNothing(): void
    {
        $this->insertProofsOf($live = $this->insertSession());

        Event::fake([ModelsPruned::class]);

        self::assertSame(0, app(SessionPruning::class)->prune(pruned: static fn (): never => self::fail('Progress was reported.')));
        self::assertSame(0, app(SessionPruning::class)->count());
        self::assertSame([$live], self::rows('authentication_sessions')->pluck('id')->all());
        self::assertSame(2, self::rows('authentication_proofs')->count());

        Event::assertNotDispatched(ModelsPruned::class);
    }

    /**
     * The cutoff is read once, when the run starts: a retention changed while
     * the run is under way neither fails it nor moves the cutoff of its later
     * chunks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCutoffIsReadOnceWhenTheRunStarts(): void
    {
        for ($index = 0; $index < 3; $index++) {
            $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));
        }

        $total = app(SessionPruning::class)->prune(1, static function (): void {
            config()->set('authentication.session.prune_after_days', 'thirty');
        });

        self::assertSame(3, $total);
        self::assertSame(0, self::rows('authentication_sessions')->count());
    }

    /**
     * Inside a caller's transaction every chunk is provisional: rolling the
     * caller's transaction back brings every pruned session back with its
     * proofs and provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOuterRollbackBringsEveryChunkBack(): void
    {
        for ($index = 0; $index < 3; $index++) {
            $this->insertProofsOf($this->insertSession(revokedAt: Carbon::parse(self::CUTOFF)));
        }

        DB::beginTransaction();

        self::assertSame(3, app(SessionPruning::class)->prune(2));
        self::assertSame(0, self::rows('authentication_sessions')->count());

        DB::rollBack();

        self::assertSame(3, self::rows('authentication_sessions')->count());
        self::assertSame(6, self::rows('authentication_proofs')->count());
        self::assertSame(3, self::rows('authentication_provenance')->count());
    }

    /**
     * A progress callback that throws stops the run: the chunk it was told of
     * stays deleted, and no later chunk is pruned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingCallbackStopsTheRunWithEarlierChunksDeleted(): void
    {
        for ($index = 0; $index < 3; $index++) {
            $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));
        }

        try {
            app(SessionPruning::class)->prune(2, static function (): never {
                throw new \RuntimeException('Progress failed.');
            });

            self::fail('The run went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Progress failed.', $exception->getMessage());
        }

        self::assertSame(1, self::rows('authentication_sessions')->count());
    }

    /**
     * A `ModelsPruned` listener that throws stops the run the same way, before
     * the callback hears of the chunk.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerStopsTheRunWithEarlierChunksDeleted(): void
    {
        for ($index = 0; $index < 3; $index++) {
            $this->insertSession(revokedAt: Carbon::parse(self::CUTOFF));
        }

        Event::listen(ModelsPruned::class, static function (): never {
            throw new \RuntimeException('Listener failed.');
        });

        try {
            app(SessionPruning::class)->prune(2, static fn (): never => self::fail('The callback heard of the chunk.'));

            self::fail('The run went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Listener failed.', $exception->getMessage());
        }

        self::assertSame(1, self::rows('authentication_sessions')->count());
    }

    /**
     * The configured model is the one pruned: a soft-deleting model has its
     * ended sessions deleted outright, with their proofs, and a session it
     * already soft-deleted is outside its scope, so it is neither counted nor
     * pruned and keeps its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASoftDeletingModelPrunesOutrightAndLeavesWhatItSoftDeleted(): void
    {
        $this->createOnPrimaryAndReplica('soft_deleting_pruning_sessions', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('guard');
            $table->dateTime('revoked_at', 0)->nullable();
            $table->dateTime('idle_expires_at', 0);
            $table->dateTime('absolute_expires_at', 0)->nullable();
            $table->softDeletes();
        });

        config()->set('authentication.session.model', SoftDeletingPruningSession::class);

        $future = Carbon::parse(self::NOW)->addDays(30);
        $ended  = Carbon::parse(self::CUTOFF);

        self::rows('soft_deleting_pruning_sessions')->insert([
            ['guard' => 'api', 'revoked_at' => $ended, 'idle_expires_at' => $future, 'absolute_expires_at' => null, 'deleted_at' => null],
            ['guard' => 'api', 'revoked_at' => $ended, 'idle_expires_at' => $future, 'absolute_expires_at' => null, 'deleted_at' => $ended],
        ]);

        $this->insertProofsOf('1');
        $this->insertProofsOf('2');

        Event::fake([ModelsPruned::class]);

        self::assertSame(1, app(SessionPruning::class)->count());
        self::assertSame(1, app(SessionPruning::class)->prune());
        self::assertSame(['2'], array_map(strval(...), self::rows('soft_deleting_pruning_sessions')->pluck('id')->all()));
        self::assertSame(['2', '2'], self::rows('authentication_proofs')->pluck('session_id')->all());
        self::assertSame(['2'], self::rows('authentication_provenance')->pluck('session_id')->all());

        Event::assertDispatched(ModelsPruned::class, static fn (ModelsPruned $event): bool => $event->model === SoftDeletingPruningSession::class && $event->count === 1);
    }

    /**
     * Register the lagging replica and make its split connection the default.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Run the call and return the queries it made on the split connection, as
     * their SQL without quoting and their bindings.
     *
     * @param  \Closure(): mixed  $call
     * @return list<array{0: string, 1: array<mixed>}>
     */
    private function queriesOf(\Closure $call): array
    {
        $connection = DB::connection(self::SPLIT_CONNECTION);

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        try {
            $call();
        } finally {
            $connection->disableQueryLog();
        }

        return array_map(
            static fn (array $query): array => [str_replace(['"', '`'], '', $query['query']), $query['bindings']],
            $connection->getQueryLog(),
        );
    }

    /**
     * A query of the table on the primary, through the split connection's
     * writer.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private static function rows(string $table): Builder
    {
        return DB::table($table)->useWritePdo();
    }

    /**
     * Record two proofs and a provenance for the session key, as rows.
     *
     * @param  string  $sessionId
     * @return void
     */
    private function insertProofsOf(string $sessionId): void
    {
        foreach (['first_factor', 'additional_factor'] as $kind) {
            self::rows('authentication_proofs')->insert([
                'id'                   => (string) Str::uuid7(),
                'session_id'           => $sessionId,
                'kind'                 => $kind,
                'purpose'              => 'sign_in',
                'method'               => 'password',
                'channel_kind'         => 'password',
                'methods'              => '["pwd"]',
                'authenticatable_type' => 'users',
                'authenticatable_id'   => '1',
                'guard'                => 'api',
                'authenticated_at'     => Carbon::parse(self::NOW),
                'created_at'           => Carbon::parse(self::NOW),
            ]);
        }

        self::rows('authentication_provenance')->insert(['session_id' => $sessionId, 'connection_id' => 'connection-7', 'created_at' => Carbon::parse(self::NOW)]);
    }

    /**
     * Insert one session of the shipped table and return its key.
     *
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @return string
     */
    private function insertSession(?Carbon $revokedAt = null, ?Carbon $idle = null): string
    {
        $row = $this->sessionRow($revokedAt, $idle);

        self::rows('authentication_sessions')->insert($row);

        return $row['id'];
    }

    /**
     * One row of the shipped table: a session of the `api` guard whose
     * deadlines are a month ahead unless given.
     *
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @return array<string, mixed>&array{id: string}
     */
    private function sessionRow(?Carbon $revokedAt = null, ?Carbon $idle = null): array
    {
        $future = Carbon::parse(self::NOW)->addDays(30);

        return [
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'idle_expires_at'      => $idle ?? $future,
            'absolute_expires_at'  => $future->copy()->addDays(30),
            'revoked_at'           => $revokedAt,
            'revoked_reason'       => $revokedAt === null ? null : 'revoked',
            'signed_in_at'         => Carbon::parse(self::NOW),
            'created_at'           => Carbon::parse(self::NOW),
            'updated_at'           => Carbon::parse(self::NOW),
        ];
    }
}
