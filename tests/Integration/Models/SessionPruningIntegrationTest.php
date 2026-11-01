<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Carbon\Carbon;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\PrunesSessions;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Integration\Fixtures\ScopedRenamedPruningSession;
use Tests\TestCase;

/**
 * Integration tests for pruning sessions with Laravel's `model:prune`, against
 * the shipped table on each supported database: which ended sessions are
 * deleted at each boundary of the retention, and how a custom model opts in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(PrunesSessions::class)]
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

        Artisan::call('model:prune', ['--model' => [Session::class]]);

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

        Artisan::call('model:prune', ['--model' => [Session::class]]);

        self::assertEqualsCanonicalizing(
            ['client-ended-now', 'client-ends-next-second', 'client-revoked-six-days-ago'],
            DB::table('authentication_sessions')->pluck('client_name')->all(),
        );

        config()->set('authentication.session.prune_after_days', 0);

        Artisan::call('model:prune', ['--model' => [Session::class]]);

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

        Artisan::call('model:prune', ['--model' => [Session::class], '--pretend' => true]);

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

        Artisan::call('model:prune', ['--model' => [Session::class], '--chunk' => 10]);

        self::assertSame(['client-live'], DB::table('authentication_sessions')->pluck('client_name')->all());
    }

    /**
     * A custom model opts in with the trait alone: pruning reads its renamed
     * columns, and its own global scope still limits what is pruned, so an
     * ended session the scope excludes is kept.
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

        Artisan::call('model:prune', ['--model' => [ScopedRenamedPruningSession::class]]);

        self::assertEqualsCanonicalizing([$live, $other], DB::table('scoped_renamed_pruning_sessions')->pluck('id')->all());
    }

    /**
     * Insert one session of the shipped table.
     *
     * @param  string  $name
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @param  ?\Carbon\Carbon  $absolute
     * @param  ?\Carbon\Carbon  $createdAt
     * @return void
     */
    private function insertSession(string $name, ?Carbon $revokedAt = null, ?Carbon $idle = null, ?Carbon $absolute = null, ?Carbon $createdAt = null): void
    {
        DB::table('authentication_sessions')->insert($this->sessionRow($name, $revokedAt, $idle, $absolute, $createdAt));
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
