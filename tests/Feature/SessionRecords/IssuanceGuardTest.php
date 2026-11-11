<?php

declare(strict_types = 1);

namespace Tests\Feature\SessionRecords;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\TestCase;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the issuance guard write on a session's own row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuanceGuard::class)]
final class IssuanceGuardTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithSessionRecords;

    /** @var string The table of the session model that renames the guard's column. */
    private const string RENAMED_TABLE = 'renamed_guard_sessions';

    /**
     * Create the stub sessions' tables, one of them with the guard's column
     * renamed.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createSessionRecordTable('stub_sessions');
        self::createSessionRecordTable(self::RENAMED_TABLE);

        Schema::table(self::RENAMED_TABLE, static function (Blueprint $blueprint): void {
            $blueprint->renameColumn('issuance_sequence', 'issued_tokens');
        });
    }

    /**
     * Drop the stub sessions' tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_sessions');
        Schema::dropIfExists(self::RENAMED_TABLE);

        parent::tearDown();
    }

    /**
     * Each write increments the session's issuance sequence once with a single
     * `UPDATE`, touching nothing else.
     *
     * @return void
     */
    public function testEachWriteIncrementsTheSessionsSequenceOnce(): void
    {
        $session = self::storedSession();
        $other   = self::storedSession();
        $before  = self::withoutIssuanceGuard((array) DB::table('stub_sessions')->where('id', $session->getKey())->first());
        $grammar = DB::connection()->getQueryGrammar();

        $queries = self::recordQueries(static function () use ($session): void {
            self::assertTrue(IssuanceGuard::write($session));
            self::assertTrue(IssuanceGuard::write($session));
        });

        self::assertCount(2, $queries);
        self::assertSame(sprintf(
            'update %s set %s = %s + 1 where %s = ?',
            $grammar->wrapTable('stub_sessions'),
            $grammar->wrap('issuance_sequence'),
            $grammar->wrap('issuance_sequence'),
            $grammar->wrap('id'),
        ), $queries[0]->sql);
        self::assertSame([$session->getKey()], $queries[0]->bindings);
        self::assertSame(2, self::issuanceGuardWrites($session->getKey(), 'stub_sessions'));
        self::assertSame($before, self::withoutIssuanceGuard((array) DB::table('stub_sessions')->where('id', $session->getKey())->first()));
        self::assertSame(0, self::issuanceGuardWrites($other->getKey(), 'stub_sessions'));
    }

    /**
     * The write fires no model event and leaves the in-memory session alone.
     *
     * @return void
     */
    public function testTheWriteFiresNoModelEventAndLeavesTheModelAlone(): void
    {
        $session = self::storedSession();
        $fired   = [];

        $record = static function (string $event) use (&$fired): \Closure {
            return static function () use (&$fired, $event): void {
                $fired[] = $event;
            };
        };

        StubSession::saving($record('saving'));
        StubSession::updating($record('updating'));
        StubSession::updated($record('updated'));
        StubSession::saved($record('saved'));

        self::assertTrue(IssuanceGuard::write($session));
        self::assertSame([], $fired);
        self::assertSame(0, $session->getAttribute('issuance_sequence'));
        self::assertFalse($session->isDirty());
    }

    /**
     * A model that names its own column has that column incremented.
     *
     * @return void
     */
    public function testAModelThatRenamesTheColumnHasItsOwnColumnIncremented(): void
    {
        $session = new class extends StubSession {
            /** @var string|null The table associated with the model. */
            protected $table = 'renamed_guard_sessions';

            /**
             * Column name holding the session's issuance sequence.
             *
             * @return string
             */
            #[\Override]
            public function getIssuanceSequenceName(): string
            {
                return 'issued_tokens';
            }
        };

        $session->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        self::assertTrue(IssuanceGuard::write($session));
        self::assertEquals(1, DB::table(self::RENAMED_TABLE)->where('id', $session->getKey())->value('issued_tokens'));
    }

    /**
     * A session whose row no longer exists is reported as not written.
     *
     * @return void
     */
    public function testASessionWhoseRowIsGoneIsNotWritten(): void
    {
        $session = self::storedSession();

        DB::table('stub_sessions')->where('id', $session->getKey())->delete();

        self::assertFalse(IssuanceGuard::write($session));
    }

    /**
     * Holding the guard of a row that is gone is a `LogicException`.
     *
     * @return void
     */
    public function testHoldingTheGuardOfARowThatIsGoneIsALogicError(): void
    {
        $session = self::storedSession();

        IssuanceGuard::hold($session);

        self::assertSame(1, self::issuanceGuardWrites($session->getKey(), 'stub_sessions'));

        DB::table('stub_sessions')->where('id', $session->getKey())->delete();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The session\'s row no longer exists, so its issuance guard cannot be written.');

        IssuanceGuard::hold($session);
    }

    /**
     * A session with no key is a `LogicException`, without a query.
     *
     * @return void
     */
    public function testASessionWithoutAKeyIsALogicError(): void
    {
        $queries = self::recordQueries(static function (): void {
            try {
                IssuanceGuard::write(new StubSession);

                self::fail('A session without a key was written.');
            } catch (\LogicException $exception) {
                self::assertSame('The issuance guard can only be written for a session that has a key.', $exception->getMessage());
            }
        });

        self::assertSame([], $queries);
    }

    /**
     * A live stub session, stored at a fixed time with nothing issued yet.
     *
     * @return \Tests\Unit\Stubs\StubSession
     */
    private static function storedSession(): StubSession
    {
        $session = new StubSession;

        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'owner',
            'authenticatable_id'   => '1',
            'issuance_sequence'    => 0,
            'updated_at'           => Carbon::parse('2026-04-06 12:00:00'),
        ])->save();

        return $session;
    }

    /**
     * The queries the callback runs, in order.
     *
     * @param  \Closure(): void  $callback
     * @return list<\Illuminate\Database\Events\QueryExecuted>
     */
    private static function recordQueries(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query;
        });

        $callback();

        return $queries;
    }
}
