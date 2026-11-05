<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\Carbon;
use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Console\PruneSessionsCommand;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SessionPruning;
use Tests\Integration\Fixtures\IntegerKeyPruningSession;
use Tests\Integration\Fixtures\ScopedRenamedPruningSession;
use Tests\Integration\Fixtures\SoftDeletingPruningSession;
use Tests\TestCase;

/**
 * Integration tests for pruning sessions with `authentication:prune-sessions`,
 * against the shipped table on each supported database: which ended sessions
 * are deleted at each boundary of the retention, with their proofs and
 * provenance, and how a configured custom model is pruned, an integer-keyed and
 * a soft-deleting one included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPruning::class)]
#[CoversClass(PruneSessionsCommand::class)]
final class SessionPruningIntegrationTest extends TestCase
{
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
     * Release the clock and drop the custom model's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Schema::dropIfExists('scoped_renamed_pruning_sessions');
        Schema::dropIfExists('integer_key_pruning_sessions');
        Schema::dropIfExists('soft_deleting_pruning_sessions');

        parent::tearDown();
    }

    /**
     * A session revoked, or past either deadline, at or before the cutoff is
     * pruned; one that ended a second after it is kept, as is a live session
     * however long ago it was created.
     *
     * @return void
     */
    public function testPrunesSessionsWhoseSessionEndedAtOrBeforeTheCutoff(): void
    {
        $cutoff = Carbon::parse(self::CUTOFF);
        $future = Carbon::parse(self::NOW)->addDays(30);

        $this->insertSession('revoked-before', revokedAt: $cutoff->copy()->subSecond());
        $this->insertSession('revoked-at', revokedAt: $cutoff);
        $this->insertSession('revoked-after', revokedAt: $cutoff->copy()->addSecond());
        $this->insertSession('idle-before', idle: $cutoff->copy()->subSecond());
        $this->insertSession('idle-at', idle: $cutoff);
        $this->insertSession('idle-after', idle: $cutoff->copy()->addSecond());
        $this->insertSession('absolute-before', idle: $future, absolute: $cutoff->copy()->subSecond());
        $this->insertSession('absolute-at', idle: $future, absolute: $cutoff);
        $this->insertSession('absolute-after', idle: $future, absolute: $cutoff->copy()->addSecond());
        $this->insertSession('live', createdAt: Carbon::parse('2020-01-01 00:00:00'));

        Artisan::call('authentication:prune-sessions');

        self::assertEqualsCanonicalizing(
            ['client-revoked-after', 'client-idle-after', 'client-absolute-after', 'client-live'],
            DB::table('authentication_sessions')->pluck('client_name')->all(),
        );
    }

    /**
     * The retention is read when pruning runs: with 0 days a session is pruned
     * from the second it ended, and a digit string, as `env()` returns one,
     * counts as its number of days.
     *
     * @return void
     */
    public function testRetentionIsReadWhenPruningRuns(): void
    {
        $now = Carbon::parse(self::NOW);

        $this->insertSession('ended-now', idle: $now);
        $this->insertSession('ends-next-second', idle: $now->copy()->addSecond());
        $this->insertSession('revoked-a-week-ago', revokedAt: $now->copy()->subDays(7));
        $this->insertSession('revoked-six-days-ago', revokedAt: $now->copy()->subDays(6));

        config()->set('authentication.session.prune_after_days', '7');

        Artisan::call('authentication:prune-sessions');

        self::assertEqualsCanonicalizing(
            ['client-ended-now', 'client-ends-next-second', 'client-revoked-six-days-ago'],
            DB::table('authentication_sessions')->pluck('client_name')->all(),
        );

        config()->set('authentication.session.prune_after_days', 0);

        Artisan::call('authentication:prune-sessions');

        self::assertEqualsCanonicalizing(['client-ends-next-second'], DB::table('authentication_sessions')->pluck('client_name')->all());
    }

    /**
     * `--pretend` counts the sessions that would be pruned and deletes nothing.
     *
     * @return void
     */
    public function testPretendCountsWithoutDeleting(): void
    {
        $this->insertSession('revoked', revokedAt: Carbon::parse(self::CUTOFF));
        $this->insertSession('live');

        Artisan::call('authentication:prune-sessions', ['--pretend' => true]);

        self::assertStringContainsString('1 [' . Session::class . '] records will be pruned.', Artisan::output());
        self::assertSame(2, DB::table('authentication_sessions')->count());
    }

    /**
     * More sessions than one chunk are all pruned, in chunks, and the live ones
     * are kept.
     *
     * @return void
     */
    public function testPrunesInChunks(): void
    {
        $rows = [];

        for ($index = 0; $index < 25; $index++) {
            $rows[] = $this->sessionRow('revoked-' . $index, revokedAt: Carbon::parse(self::CUTOFF));
        }

        DB::table('authentication_sessions')->insert($rows);

        $this->insertSession('live');

        Artisan::call('authentication:prune-sessions', ['--chunk' => '10']);

        self::assertSame(['client-live'], DB::table('authentication_sessions')->pluck('client_name')->all());
    }

    /**
     * A configured custom model is pruned with nothing of its own: pruning
     * reads its renamed columns, and its own global scope still limits what is
     * pruned, so an ended session the scope excludes is kept.
     *
     * @return void
     */
    public function testACustomModelPrunesThroughItsOwnColumnsAndScope(): void
    {
        Schema::create('scoped_renamed_pruning_sessions', static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('guard');
            $table->dateTime('ended_at', 0)->nullable();
            $table->dateTime('idle_until', 0);
            $table->dateTime('valid_until', 0);
        });

        $cutoff = Carbon::parse(self::CUTOFF);
        $future = Carbon::parse(self::NOW)->addDays(30);

        DB::table('scoped_renamed_pruning_sessions')->insert([
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => $cutoff, 'idle_until' => $future, 'valid_until' => $future],
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $cutoff, 'valid_until' => $future],
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $future, 'valid_until' => $cutoff],
            ['id' => $live = (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $future, 'valid_until' => $future],
            ['id' => $other = (string) Str::uuid7(), 'guard' => 'web', 'ended_at' => null, 'idle_until' => $cutoff, 'valid_until' => $future],
        ]);

        config()->set('authentication.session.model', ScopedRenamedPruningSession::class);

        Artisan::call('authentication:prune-sessions');

        self::assertEqualsCanonicalizing([$live, $other], DB::table('scoped_renamed_pruning_sessions')->pluck('id')->all());
    }

    /**
     * Pruning a session deletes the proofs and the provenance recorded for it
     * in the same chunk, and keeps those of the sessions it keeps; it reports
     * the sessions it pruned, not their proofs.
     *
     * @return void
     */
    public function testPruningASessionDeletesItsProofsAndProvenance(): void
    {
        $pruned = $this->insertSession('revoked', revokedAt: Carbon::parse(self::CUTOFF));
        $kept   = $this->insertSession('live');

        foreach ([$pruned, $kept] as $id) {
            $this->insertProofsOf($id);
        }

        Event::fake([ModelsPruned::class]);

        Artisan::call('authentication:prune-sessions');

        self::assertSame([$kept], DB::table('authentication_sessions')->pluck('id')->all());
        self::assertSame([$kept, $kept], DB::table('authentication_proofs')->pluck('session_id')->all());
        self::assertSame([$kept], DB::table('authentication_provenance')->pluck('session_id')->all());

        Event::assertDispatched(ModelsPruned::class, static fn (ModelsPruned $event): bool => $event->model === Session::class && $event->count === 1);
        Event::assertDispatchedTimes(ModelsPruned::class, 1);
    }

    /**
     * A pending session whose credential expired at or before the cutoff ended
     * then, so it is pruned with its proofs and provenance like any ended
     * session; a pending one still waiting is kept with its own.
     *
     * @return void
     */
    public function testAnExpiredPendingSessionIsPrunedWithItsProofs(): void
    {
        $pending = ['status' => 'pending', 'requires' => '["mfa"]', 'pending_key' => hash('sha256', 'pending-secret')];
        $expired = (string) Str::uuid7();
        $waiting = (string) Str::uuid7();

        DB::table('authentication_sessions')->insert([...$this->sessionRow('expired', idle: Carbon::parse(self::CUTOFF)), ...$pending, 'id' => $expired]);
        DB::table('authentication_sessions')->insert([...$this->sessionRow('waiting', idle: Carbon::parse(self::NOW)->addMinutes(5)), ...$pending, 'id' => $waiting]);

        foreach ([$expired, $waiting] as $id) {
            $this->insertProofsOf($id);
        }

        Artisan::call('authentication:prune-sessions');

        self::assertSame([$waiting], DB::table('authentication_sessions')->pluck('id')->all());
        self::assertSame([$waiting, $waiting], DB::table('authentication_proofs')->pluck('session_id')->all());
        self::assertSame([$waiting], DB::table('authentication_provenance')->pluck('session_id')->all());
    }

    /**
     * Chunked pruning deletes each chunk's proofs with its sessions, and the
     * running total `ModelsPruned` reports counts sessions.
     *
     * @return void
     */
    public function testChunkedPruningDeletesEachChunksProofs(): void
    {
        for ($index = 0; $index < 5; $index++) {
            $this->insertProofsOf($this->insertSession('revoked-' . $index, revokedAt: Carbon::parse(self::CUTOFF)));
        }

        $live = $this->insertSession('live');

        $this->insertProofsOf($live);

        Event::fake([ModelsPruned::class]);

        Artisan::call('authentication:prune-sessions', ['--chunk' => '2']);

        self::assertSame([$live], DB::table('authentication_sessions')->pluck('id')->all());
        self::assertSame([$live], array_values(array_unique(DB::table('authentication_proofs')->pluck('session_id')->all())));
        self::assertSame([$live], DB::table('authentication_provenance')->pluck('session_id')->all());

        $totals = array_map(static fn (array $dispatched): mixed => $dispatched[0]->count ?? null, Event::dispatched(ModelsPruned::class)->all());

        self::assertSame([2, 4, 5], $totals);
    }

    /**
     * A session model with an integer key has its sessions' proofs and
     * provenance pruned by the key as the string they record it as.
     *
     * @return void
     */
    public function testAnIntegerKeyedModelPrunesItsSessionsProofs(): void
    {
        config()->set('authentication.session.table', 'integer_key_pruning_sessions');

        Schema::create('integer_key_pruning_sessions', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('guard');
            $table->dateTime('revoked_at', 0)->nullable();
            $table->dateTime('idle_expires_at', 0);
            $table->dateTime('absolute_expires_at', 0)->nullable();
        });

        $future = Carbon::parse(self::NOW)->addDays(30);

        DB::table('integer_key_pruning_sessions')->insert([
            ['guard' => 'api', 'revoked_at' => Carbon::parse(self::CUTOFF), 'idle_expires_at' => $future, 'absolute_expires_at' => $future],
            ['guard' => 'api', 'revoked_at' => null, 'idle_expires_at' => $future, 'absolute_expires_at' => $future],
        ]);

        $this->insertProofsOf('1');
        $this->insertProofsOf('2');
        $this->insertProofsOf('12');

        config()->set('authentication.session.model', IntegerKeyPruningSession::class);

        Artisan::call('authentication:prune-sessions');

        Schema::dropIfExists('integer_key_pruning_sessions');

        self::assertEqualsCanonicalizing(['2', '2', '12', '12'], DB::table('authentication_proofs')->pluck('session_id')->all());
        self::assertEqualsCanonicalizing(['2', '12'], DB::table('authentication_provenance')->pluck('session_id')->all());
    }

    /**
     * A session model that soft-deletes has its ended sessions deleted outright
     * with their proofs and provenance, rather than marked deleted, which would
     * leave them out of every later prune and keep them for good; a session it
     * already soft-deleted is outside its scope, so it is left with its own.
     *
     * @return void
     */
    public function testASoftDeletingModelPrunesItsSessionsOutright(): void
    {
        Schema::create('soft_deleting_pruning_sessions', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('guard');
            $table->dateTime('revoked_at', 0)->nullable();
            $table->dateTime('idle_expires_at', 0);
            $table->dateTime('absolute_expires_at', 0)->nullable();
            $table->softDeletes();
        });

        $future = Carbon::parse(self::NOW)->addDays(30);
        $cutoff = Carbon::parse(self::CUTOFF);

        DB::table('soft_deleting_pruning_sessions')->insert([
            ['guard' => 'api', 'revoked_at' => $cutoff, 'idle_expires_at' => $future, 'absolute_expires_at' => $future, 'deleted_at' => null],
            ['guard' => 'api', 'revoked_at' => null, 'idle_expires_at' => $future, 'absolute_expires_at' => $future, 'deleted_at' => null],
            ['guard' => 'api', 'revoked_at' => $cutoff, 'idle_expires_at' => $future, 'absolute_expires_at' => $future, 'deleted_at' => $cutoff],
        ]);

        $this->insertProofsOf('1');
        $this->insertProofsOf('2');
        $this->insertProofsOf('3');

        config()->set('authentication.session.model', SoftDeletingPruningSession::class);

        Artisan::call('authentication:prune-sessions');

        $remaining = DB::table('soft_deleting_pruning_sessions')->get(['id', 'deleted_at'])->all();

        Schema::dropIfExists('soft_deleting_pruning_sessions');

        usort($remaining, static fn (object $a, object $b): int => (int) $a->id <=> (int) $b->id);

        self::assertSame(['2', '3'], array_map(static fn (object $row): string => (string) $row->id, $remaining));
        self::assertNull($remaining[0]->deleted_at);
        self::assertNotNull($remaining[1]->deleted_at);
        self::assertEqualsCanonicalizing(['2', '2', '3', '3'], DB::table('authentication_proofs')->pluck('session_id')->all());
        self::assertEqualsCanonicalizing(['2', '3'], DB::table('authentication_provenance')->pluck('session_id')->all());
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
            DB::table('authentication_proofs')->insert([
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

        DB::table('authentication_provenance')->insert(['session_id' => $sessionId, 'connection_id' => 'connection-7', 'created_at' => Carbon::parse(self::NOW)]);
    }

    /**
     * Insert one session of the shipped table and return its key.
     *
     * @param  string  $name
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @param  ?\Carbon\Carbon  $absolute
     * @param  ?\Carbon\Carbon  $createdAt
     * @return string
     */
    private function insertSession(string $name, ?Carbon $revokedAt = null, ?Carbon $idle = null, ?Carbon $absolute = null, ?Carbon $createdAt = null): string
    {
        $id = (string) Str::uuid7();

        DB::table('authentication_sessions')->insert([...$this->sessionRow($name, $revokedAt, $idle, $absolute, $createdAt), 'id' => $id]);

        return $id;
    }

    /**
     * One row of the shipped table: a session of the `api` guard whose
     * deadlines are a month ahead unless given.
     *
     * @param  string  $name
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @param  ?\Carbon\Carbon  $absolute
     * @param  ?\Carbon\Carbon  $createdAt
     * @return array<string, mixed>
     */
    private function sessionRow(string $name, ?Carbon $revokedAt = null, ?Carbon $idle = null, ?Carbon $absolute = null, ?Carbon $createdAt = null): array
    {
        $future = Carbon::parse(self::NOW)->addDays(30);

        return [
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'client_name'          => 'client-' . $name,
            'idle_expires_at'      => $idle     ?? $future,
            'absolute_expires_at'  => $absolute ?? $future->copy()->addDays(30),
            'revoked_at'           => $revokedAt,
            'revoked_reason'       => $revokedAt === null ? null : 'revoked',
            'signed_in_at'         => $createdAt ?? Carbon::parse(self::NOW),
            'created_at'           => $createdAt ?? Carbon::parse(self::NOW),
            'updated_at'           => $createdAt ?? Carbon::parse(self::NOW),
        ];
    }
}
