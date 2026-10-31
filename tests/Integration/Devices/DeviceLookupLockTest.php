<?php

declare(strict_types = 1);

namespace Tests\Integration\Devices;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Devices\DeviceLookup;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\TestCase;

/**
 * Integration tests for the locking device lookup a proof of recent
 * authentication reads its device with: one read of the device's row by key,
 * with the engine's row lock (none on SQLite), where the plain lookup takes
 * none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceLookup::class)]
final class DeviceLookupLockTest extends TestCase
{
    use InteractsWithDevices;

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
        $device = new Device;
        $device->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        DB::transaction(static fn (): mixed => DeviceLookup::lock($device->getKey()));
        DeviceLookup::find($device->getKey());

        $grammar = DB::connection()->getQueryGrammar();
        $lock    = DB::connection()->getDriverName() === 'sqlite' ? '' : ' for update';
        $read    = sprintf('select * from %s where %s = ? limit 1', $grammar->wrapTable('devices'), $grammar->wrap('devices.id'));

        self::assertSame([$read . $lock, $read], $statements);
    }
}
