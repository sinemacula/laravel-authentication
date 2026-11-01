<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the guarded refresh-state writes and the locking re-read,
 * against a real session table on whichever engine the suite runs on, and a
 * session kept on a second connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshRotationStore::class)]
final class RefreshRotationStoreTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Rotation id the session currently holds. */
    private const string CURRENT = 'current-rotation-id';

    /** @var string Rotation id the session rotates to. */
    private const string NEXT = 'next-rotation-id';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock and create the session table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        self::createSessionRecordTable('stub_sessions');
    }

    /**
     * Release the clock and drop the session table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::statement('drop table if exists stub_sessions');

        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A rotation records the next digest as current, the presented one as
     * previous, the rotation time, and the new idle deadline, then mirrors them
     * on the in-memory session as persisted state.
     *
     * @return void
     */
    public function testRotateRecordsTheRotationAndMirrorsIt(): void
    {
        $session = $this->record();
        $idle    = $this->now->addDays(90);

        self::assertTrue($this->store()->rotate($session, self::CURRENT, self::NEXT, $idle, $this->now));

        $row = $this->row($session);

        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $row['previous_refresh_key']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['refresh_rotated_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($idle->getTimestamp(), Carbon::parse($row['idle_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type

        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $session->getRefreshKey());
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $session->getPreviousRefreshKey());
        self::assertSame($this->now->getTimestamp(), $session->getRefreshRotatedAt()?->getTimestamp());
        self::assertSame($idle->getTimestamp(), $session->getIdleExpiresAt()?->getTimestamp());
        self::assertFalse($session->isDirty());
    }

    /**
     * Rows of `[change committed after the session was loaded]` that the swap
     * must not overwrite.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesSinceTheSessionWasLoaded(): iterable
    {
        yield from [
            'rotated elsewhere'       => [['refresh_key' => RefreshTokenHasher::hash('elsewhere')]],
            'revoked'                 => [['revoked_at' => '2026-04-06 11:59:00']],
            'idle deadline moved'     => [['idle_expires_at' => '2026-07-06 12:00:00']],
            'absolute deadline moved' => [['absolute_expires_at' => '2026-05-06 12:00:00']],
        ];
    }

    /**
     * The swap applies only to the state the session was loaded with: after a
     * concurrent rotation, revocation, or deadline change it affects no row,
     * reports so, and leaves the in-memory session as it was.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideChangesSinceTheSessionWasLoaded')]
    public function testRotateMissesAfterAChangeSinceTheSessionWasLoaded(array $change): void
    {
        $session = $this->record();

        DB::table('stub_sessions')->where('id', $session->id)->update($change);

        $before = $this->row($session);

        self::assertFalse($this->store()->rotate($session, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame($before, $this->row($session));
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $session->getRefreshKey());
        self::assertNull($session->getPreviousRefreshKey());
    }

    /**
     * A switch records the target, the switch time, the rotation and both
     * deadlines, on the row and on the in-memory session.
     *
     * @return void
     */
    public function testSwitchPrincipalRecordsTheTargetAndMirrorsIt(): void
    {
        $session  = $this->record([...self::recordedPrincipal(new PlainPrincipalFixture('p-1')), 'principal_type' => 'previous-type']);
        $idle     = $this->now->addDays(30);
        $absolute = $this->now->addDays(60);

        self::assertTrue($this->store()->switchPrincipal($session, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), true, [$idle, $absolute], $this->now));

        $row = $this->row($session);

        self::assertSame(PlainPrincipalFixture::class, $row['principal_type']);
        self::assertSame('p-2', $row['principal_id']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['principal_switched_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $row['previous_refresh_key']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['refresh_rotated_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($idle->getTimestamp(), Carbon::parse($row['idle_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($absolute->getTimestamp(), Carbon::parse($row['absolute_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type

        self::assertSame('p-2', $session->getAttribute('principal_id'));
        self::assertSame($this->now->getTimestamp(), $session->getPrincipalSwitchedAt()?->getTimestamp());
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $session->getRefreshKey());
        self::assertSame($absolute->getTimestamp(), $session->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertFalse($session->isDirty());
    }

    /**
     * A rotation for the principal the session already records moves the
     * rotation and the deadlines but records no switch.
     *
     * @return void
     */
    public function testSwitchPrincipalWithoutSwitchingOnlyRotates(): void
    {
        $session = $this->record(self::recordedPrincipal(new PlainPrincipalFixture('p-1')));

        $deadlines = [$this->now->addDays(30), $this->now->addDays(60)];

        self::assertTrue($this->store()->switchPrincipal($session, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), false, $deadlines, $this->now));

        $row = $this->row($session);

        self::assertSame('p-1', $row['principal_id']);
        self::assertNull($row['principal_switched_at']);
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
    }

    /**
     * Rows of `[change committed since the session was loaded]` for a switch.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesBeforeASwitch(): iterable
    {
        yield from [
            'rotated elsewhere'       => [['refresh_key' => RefreshTokenHasher::hash('elsewhere')]],
            'revoked'                 => [['revoked_at' => '2026-04-06 11:59:00']],
            'idle deadline moved'     => [['idle_expires_at' => '2026-07-06 12:00:00']],
            'absolute deadline moved' => [['absolute_expires_at' => '2026-05-06 12:00:00']],
            'switched elsewhere'      => [['principal_id' => 'p-3']],
            'principal type changed'  => [['principal_type' => 'other']],
        ];
    }

    /**
     * The switch applies only to the state the session was loaded with: after a
     * concurrent rotation, revocation, deadline change or switch it affects no
     * row, reports so, and leaves the in-memory session as it was.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideChangesBeforeASwitch')]
    public function testSwitchPrincipalMissesAfterAChangeSinceTheSessionWasLoaded(array $change): void
    {
        $session = $this->record(self::recordedPrincipal(new PlainPrincipalFixture('p-1')));

        DB::table('stub_sessions')->where('id', $session->id)->update($change);

        $before = $this->row($session);

        $deadlines = [$this->now->addDays(30), $this->now->addDays(60)];

        self::assertFalse($this->store()->switchPrincipal($session, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), true, $deadlines, $this->now));
        self::assertSame($before, $this->row($session));
        self::assertSame('p-1', $session->getAttribute('principal_id'));
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $session->getRefreshKey());
    }

    /**
     * A revocation records the time and reason, clears both digests, and
     * mirrors them on the in-memory session.
     *
     * @return void
     */
    public function testRevokeMarksTheRowAndMirrorsIt(): void
    {
        $session = $this->record(['previous_refresh_key' => RefreshTokenHasher::hash('previous')]);

        self::assertTrue($this->store()->revoke($session, RevocationReason::ROTATION_REUSE, $this->now));

        $row = $this->row($session);

        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['revoked_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame('rotation_reuse', $row['revoked_reason']);
        self::assertNull($row['refresh_key']);
        self::assertNull($row['previous_refresh_key']);

        self::assertSame($this->now->getTimestamp(), $session->getRevokedAt()?->getTimestamp());
        self::assertSame('rotation_reuse', $session->getRevokedReason());
        self::assertNull($session->getRefreshKey());
        self::assertNull($session->getPreviousRefreshKey());
        self::assertFalse($session->isDirty());
    }

    /**
     * Revoking a session that is already revoked changes nothing and reports
     * so: the first revocation's time and reason are kept.
     *
     * @return void
     */
    public function testRevokeKeepsAnEarlierRevocation(): void
    {
        $session = $this->record(['revoked_at' => '2026-04-01 09:00:00', 'revoked_reason' => 'earlier']);
        $before  = $this->row($session);

        self::assertFalse($this->store()->revoke($session, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame($before, $this->row($session));
        self::assertSame('earlier', $session->getRevokedReason());
    }

    /**
     * The columns a revocation writes are the ones the session writer's
     * replacement writes too: the time in the model's own format, the reason,
     * and both digests cleared, and nothing else.
     *
     * @return void
     */
    public function testRevocationIsTheTimeTheReasonAndBothDigestsCleared(): void
    {
        $session = $this->record();

        self::assertSame([
            'revoked_at'           => $session->fromDateTime($this->now),
            'revoked_reason'       => 'superseded',
            'refresh_key'          => null,
            'previous_refresh_key' => null,
        ], RefreshRotationStore::revocation($session, RevocationReason::SUPERSEDED, $this->now));
        self::assertFalse($session->isDirty());
    }

    /**
     * The re-read returns the row as it now is, from the write connection, with
     * a locking read on engines that support one.
     *
     * @return void
     */
    public function testReloadReadsTheRowAsItNowIs(): void
    {
        $session = $this->record();

        DB::table('stub_sessions')->where('id', $session->id)->update(['refresh_key' => RefreshTokenHasher::hash(self::NEXT)]);

        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $fresh = $this->store()->reload($session);

        self::assertInstanceOf(StubSession::class, $fresh);
        self::assertNotSame($session, $fresh);
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $fresh->getRefreshKey());
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $session->getRefreshKey());
        self::assertCount(1, $queries);

        if (DB::connection()->getDriverName() === 'sqlite') {
            return;
        }

        self::assertStringContainsString('for update', strtolower($queries[0]));
    }

    /**
     * The re-read of a session deleted since it was loaded returns `null`.
     *
     * @return void
     */
    public function testReloadReturnsNullForADeletedSession(): void
    {
        $session = $this->record();

        DB::table('stub_sessions')->where('id', $session->id)->delete();

        self::assertNull($this->store()->reload($session));
    }

    /**
     * A rotation and a revocation change the session's own row and no other:
     * neither another session of the same owner nor one of another owner.
     *
     * @return void
     */
    public function testWritesTouchOnlyTheSessionsOwnRow(): void
    {
        $session = $this->record(['authenticatable_type' => 'owner', 'authenticatable_id' => '1']);

        $others = [
            $this->record([
                'authenticatable_type' => 'owner',
                'authenticatable_id'   => '1',
                'previous_refresh_key' => RefreshTokenHasher::hash('older'),
                'refresh_rotated_at'   => '2026-04-06 11:00:00',
            ]),
            $this->record(['authenticatable_type' => 'owner', 'authenticatable_id' => '2']),
        ];

        $before = array_map($this->row(...), $others);

        self::assertTrue($this->store()->rotate($session, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame($before, array_map($this->row(...), $others));

        self::assertTrue($this->store()->revoke($session, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame($before, array_map($this->row(...), $others));
        self::assertNotNull($this->row($session)['revoked_at']);
    }

    /**
     * A session kept on its own connection is rotated, revoked, and read again
     * on that connection, never on the default one, even when the default
     * connection holds a table of the same name with the same row.
     *
     * @return void
     */
    public function testWritesAndReadsUseTheSessionsOwnConnection(): void
    {
        self::createSessionRecordTable('authentication_sessions', 'id', SeparateConnectionSession::CONNECTION);

        $session = new SeparateConnectionSession;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'owner',
            'authenticatable_id'   => '1',
            'refresh_key'          => RefreshTokenHasher::hash(self::CURRENT),
        ])->save();

        $session = SeparateConnectionSession::query()->findOrFail($session->id);
        $twin    = (array) DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('id', $session->id)->first();

        DB::table('authentication_sessions')->insert($twin);

        self::assertTrue($this->store()->rotate($session, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $this->separateRow($session)['refresh_key']);

        self::assertTrue($this->store()->revoke($session, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame('rotation_reuse', $this->separateRow($session)['revoked_reason']);

        self::assertSame('rotation_reuse', $this->store()->reload($session)?->getRevokedReason());
        self::assertSame($twin, (array) DB::table('authentication_sessions')->where('id', $session->id)->first());
    }

    /**
     * Add the second connection a session can be kept on.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Build the store on the application's connections.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore
     */
    private function store(): RefreshRotationStore
    {
        return new RefreshRotationStore(app(ConnectionResolverInterface::class));
    }

    /**
     * Read the raw row of a session kept on its own connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionSession  $session
     * @return array<string, mixed>
     */
    private function separateRow(SeparateConnectionSession $session): array
    {
        return (array) DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('id', $session->id)->first();
    }

    /**
     * Persist a live session holding `CURRENT`, with any further state, and
     * load it back as the exchange would.
     *
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function record(array $state = []): StubSession
    {
        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(),
            'refresh_key' => RefreshTokenHasher::hash(self::CURRENT),
            ...$state,
        ])->save();

        return StubSession::query()->findOrFail($session->id);
    }

    /**
     * Read a session's raw row.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return array<string, mixed>
     */
    private function row(StubSession $session): array
    {
        return (array) DB::table('stub_sessions')->where('id', $session->id)->first();
    }
}
