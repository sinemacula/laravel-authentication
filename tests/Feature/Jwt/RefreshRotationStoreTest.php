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
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubDevice;

/**
 * Feature tests for the guarded refresh-state writes and the locking re-read,
 * against a real device table on whichever engine the suite runs on, and a
 * device kept on a second connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshRotationStore::class)]
final class RefreshRotationStoreTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Rotation id the device currently holds. */
    private const string CURRENT = 'current-rotation-id';

    /** @var string Rotation id the device rotates to. */
    private const string NEXT = 'next-rotation-id';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock and create the device table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        self::createDeviceTable('stub_devices');
    }

    /**
     * Release the clock and drop the device table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::statement('drop table if exists stub_devices');

        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A rotation records the next digest as current, the presented one as
     * previous, the rotation time, and the new idle deadline, then mirrors them
     * on the in-memory device as persisted state.
     *
     * @return void
     */
    public function testRotateRecordsTheRotationAndMirrorsIt(): void
    {
        $device = $this->device();
        $idle   = $this->now->addDays(90);

        self::assertTrue($this->store()->rotate($device, self::CURRENT, self::NEXT, $idle, $this->now));

        $row = $this->row($device);

        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $row['previous_refresh_key']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['refresh_rotated_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($idle->getTimestamp(), Carbon::parse($row['idle_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type

        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $device->getRefreshKey());
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $device->getPreviousRefreshKey());
        self::assertSame($this->now->getTimestamp(), $device->getRefreshRotatedAt()?->getTimestamp());
        self::assertSame($idle->getTimestamp(), $device->getIdleExpiresAt()?->getTimestamp());
        self::assertFalse($device->isDirty());
    }

    /**
     * Rows of `[change committed after the device was loaded]` that the swap
     * must not overwrite.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesSinceTheDeviceWasLoaded(): iterable
    {
        yield from [
            'rotated elsewhere'       => [['refresh_key' => RefreshTokenHasher::hash('elsewhere')]],
            'revoked'                 => [['revoked_at' => '2026-04-06 11:59:00']],
            'idle deadline moved'     => [['idle_expires_at' => '2026-07-06 12:00:00']],
            'absolute deadline moved' => [['absolute_expires_at' => '2026-05-06 12:00:00']],
        ];
    }

    /**
     * The swap applies only to the state the device was loaded with: after a
     * concurrent rotation, revocation, or deadline change it affects no row,
     * reports so, and leaves the in-memory device as it was.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideChangesSinceTheDeviceWasLoaded')]
    public function testRotateMissesAfterAChangeSinceTheDeviceWasLoaded(array $change): void
    {
        $device = $this->device();

        DB::table('stub_devices')->where('id', $device->id)->update($change);

        $before = $this->row($device);

        self::assertFalse($this->store()->rotate($device, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame($before, $this->row($device));
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $device->getRefreshKey());
        self::assertNull($device->getPreviousRefreshKey());
    }

    /**
     * A switch records the target, the switch time, the rotation and both
     * deadlines, on the row and on the in-memory device.
     *
     * @return void
     */
    public function testSwitchPrincipalRecordsTheTargetAndMirrorsIt(): void
    {
        $device   = $this->device([...self::recordedPrincipal(new PlainPrincipalFixture('p-1')), 'principal_type' => 'previous-type']);
        $idle     = $this->now->addDays(30);
        $absolute = $this->now->addDays(60);

        self::assertTrue($this->store()->switchPrincipal($device, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), true, [$idle, $absolute], $this->now));

        $row = $this->row($device);

        self::assertSame(PlainPrincipalFixture::class, $row['principal_type']);
        self::assertSame('p-2', $row['principal_id']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['principal_switched_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $row['previous_refresh_key']);
        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['refresh_rotated_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($idle->getTimestamp(), Carbon::parse($row['idle_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame($absolute->getTimestamp(), Carbon::parse($row['absolute_expires_at'])->getTimestamp()); // @phpstan-ignore argument.type

        self::assertSame('p-2', $device->getAttribute('principal_id'));
        self::assertSame($this->now->getTimestamp(), $device->getPrincipalSwitchedAt()?->getTimestamp());
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $device->getRefreshKey());
        self::assertSame($absolute->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertFalse($device->isDirty());
    }

    /**
     * A rotation for the principal the device already records moves the
     * rotation and the deadlines but records no switch.
     *
     * @return void
     */
    public function testSwitchPrincipalWithoutSwitchingOnlyRotates(): void
    {
        $device = $this->device(self::recordedPrincipal(new PlainPrincipalFixture('p-1')));

        $deadlines = [$this->now->addDays(30), $this->now->addDays(60)];

        self::assertTrue($this->store()->switchPrincipal($device, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), false, $deadlines, $this->now));

        $row = $this->row($device);

        self::assertSame('p-1', $row['principal_id']);
        self::assertNull($row['principal_switched_at']);
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $row['refresh_key']);
    }

    /**
     * Rows of `[change committed since the device was loaded]` for a switch.
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
     * The switch applies only to the state the device was loaded with: after a
     * concurrent rotation, revocation, deadline change or switch it affects no
     * row, reports so, and leaves the in-memory device as it was.
     *
     * @param  array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideChangesBeforeASwitch')]
    public function testSwitchPrincipalMissesAfterAChangeSinceTheDeviceWasLoaded(array $change): void
    {
        $device = $this->device(self::recordedPrincipal(new PlainPrincipalFixture('p-1')));

        DB::table('stub_devices')->where('id', $device->id)->update($change);

        $before = $this->row($device);

        $deadlines = [$this->now->addDays(30), $this->now->addDays(60)];

        self::assertFalse($this->store()->switchPrincipal($device, self::CURRENT, self::NEXT, new PlainPrincipalFixture('p-2'), true, $deadlines, $this->now));
        self::assertSame($before, $this->row($device));
        self::assertSame('p-1', $device->getAttribute('principal_id'));
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $device->getRefreshKey());
    }

    /**
     * A revocation records the time and reason, clears both digests, and
     * mirrors them on the in-memory device.
     *
     * @return void
     */
    public function testRevokeMarksTheRowAndMirrorsIt(): void
    {
        $device = $this->device(['previous_refresh_key' => RefreshTokenHasher::hash('previous')]);

        self::assertTrue($this->store()->revoke($device, RevocationReason::ROTATION_REUSE, $this->now));

        $row = $this->row($device);

        self::assertSame($this->now->getTimestamp(), Carbon::parse($row['revoked_at'])->getTimestamp()); // @phpstan-ignore argument.type
        self::assertSame('rotation_reuse', $row['revoked_reason']);
        self::assertNull($row['refresh_key']);
        self::assertNull($row['previous_refresh_key']);

        self::assertSame($this->now->getTimestamp(), $device->getRevokedAt()?->getTimestamp());
        self::assertSame('rotation_reuse', $device->getRevokedReason());
        self::assertNull($device->getRefreshKey());
        self::assertNull($device->getPreviousRefreshKey());
        self::assertFalse($device->isDirty());
    }

    /**
     * Revoking a device that is already revoked changes nothing and reports so:
     * the first revocation's time and reason are kept.
     *
     * @return void
     */
    public function testRevokeKeepsAnEarlierRevocation(): void
    {
        $device = $this->device(['revoked_at' => '2026-04-01 09:00:00', 'revoked_reason' => 'earlier']);
        $before = $this->row($device);

        self::assertFalse($this->store()->revoke($device, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame($before, $this->row($device));
        self::assertSame('earlier', $device->getRevokedReason());
    }

    /**
     * The re-read returns the row as it now is, from the write connection, with
     * a locking read on engines that support one.
     *
     * @return void
     */
    public function testReloadReadsTheRowAsItNowIs(): void
    {
        $device = $this->device();

        DB::table('stub_devices')->where('id', $device->id)->update(['refresh_key' => RefreshTokenHasher::hash(self::NEXT)]);

        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $fresh = $this->store()->reload($device);

        self::assertInstanceOf(StubDevice::class, $fresh);
        self::assertNotSame($device, $fresh);
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $fresh->getRefreshKey());
        self::assertSame(RefreshTokenHasher::hash(self::CURRENT), $device->getRefreshKey());
        self::assertCount(1, $queries);

        if (DB::connection()->getDriverName() === 'sqlite') {
            return;
        }

        self::assertStringContainsString('for update', strtolower($queries[0]));
    }

    /**
     * The re-read of a device deleted since it was loaded returns `null`.
     *
     * @return void
     */
    public function testReloadReturnsNullForADeletedDevice(): void
    {
        $device = $this->device();

        DB::table('stub_devices')->where('id', $device->id)->delete();

        self::assertNull($this->store()->reload($device));
    }

    /**
     * A rotation and a revocation change the device's own row and no other:
     * neither another device of the same owner nor one of another owner.
     *
     * @return void
     */
    public function testWritesTouchOnlyTheDevicesOwnRow(): void
    {
        $device = $this->device(['authenticatable_type' => 'owner', 'authenticatable_id' => '1']);

        $others = [
            $this->device([
                'authenticatable_type' => 'owner',
                'authenticatable_id'   => '1',
                'previous_refresh_key' => RefreshTokenHasher::hash('older'),
                'refresh_rotated_at'   => '2026-04-06 11:00:00',
            ]),
            $this->device(['authenticatable_type' => 'owner', 'authenticatable_id' => '2']),
        ];

        $before = array_map($this->row(...), $others);

        self::assertTrue($this->store()->rotate($device, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame($before, array_map($this->row(...), $others));

        self::assertTrue($this->store()->revoke($device, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame($before, array_map($this->row(...), $others));
        self::assertNotNull($this->row($device)['revoked_at']);
    }

    /**
     * A device kept on its own connection is rotated, revoked, and read again
     * on that connection, never on the default one, even when the default
     * connection holds a table of the same name with the same row.
     *
     * @return void
     */
    public function testWritesAndReadsUseTheDevicesOwnConnection(): void
    {
        self::createDeviceTable('devices', 'id', SeparateConnectionDevice::CONNECTION);

        $device = new SeparateConnectionDevice;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'owner',
            'authenticatable_id'   => '1',
            'refresh_key'          => RefreshTokenHasher::hash(self::CURRENT),
        ])->save();

        $device = SeparateConnectionDevice::query()->findOrFail($device->id);
        $twin   = (array) DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('id', $device->id)->first();

        DB::table('devices')->insert($twin);

        self::assertTrue($this->store()->rotate($device, self::CURRENT, self::NEXT, $this->now->addDays(90), $this->now));
        self::assertSame(RefreshTokenHasher::hash(self::NEXT), $this->separateRow($device)['refresh_key']);

        self::assertTrue($this->store()->revoke($device, RevocationReason::ROTATION_REUSE, $this->now));
        self::assertSame('rotation_reuse', $this->separateRow($device)['revoked_reason']);

        self::assertSame('rotation_reuse', $this->store()->reload($device)?->getRevokedReason());
        self::assertSame($twin, (array) DB::table('devices')->where('id', $device->id)->first());
    }

    /**
     * Add the second connection a device can be kept on.
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

        $config->set('database.connections.' . SeparateConnectionDevice::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
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
     * Read the raw row of a device kept on its own connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionDevice  $device
     * @return array<string, mixed>
     */
    private function separateRow(SeparateConnectionDevice $device): array
    {
        return (array) DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('id', $device->id)->first();
    }

    /**
     * Persist a live device holding `CURRENT`, with any further state, and load
     * it back as the exchange would.
     *
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function device(array $state = []): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(),
            'refresh_key' => RefreshTokenHasher::hash(self::CURRENT),
            ...$state,
        ])->save();

        return StubDevice::query()->findOrFail($device->id);
    }

    /**
     * Read a device's raw row.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return array<string, mixed>
     */
    private function row(StubDevice $device): array
    {
        return (array) DB::table('stub_devices')->where('id', $device->id)->first();
    }
}
