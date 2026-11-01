<?php

declare(strict_types = 1);

namespace Tests\Integration\SessionRecords;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\TestCase;

/**
 * Integration tests for the locking session lookup a proof of recent
 * authentication reads its session with: one read of the session's row by key,
 * with the engine's row lock (none on SQLite), where the plain lookup takes
 * none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionLookup::class)]
final class SessionLookupLockTest extends TestCase
{
    use InteractsWithSessionRecords;

    /**
     * The locking lookup reads the row by key under the engine's row lock; the
     * plain lookup runs the same read without it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockingLookupReadsTheRowUnderALock(): void
    {
        $session = new Session;
        $session->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        DB::transaction(static fn (): mixed => SessionLookup::lock($session->getKey()));
        SessionLookup::find($session->getKey());

        $grammar = DB::connection()->getQueryGrammar();
        $lock    = DB::connection()->getDriverName() === 'sqlite' ? '' : ' for update';
        $read    = sprintf('select * from %s where %s = ? limit 1', $grammar->wrapTable('authentication_sessions'), $grammar->wrap('authentication_sessions.id'));

        self::assertSame([$read . $lock, $read], $statements);
    }
}
