<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Unit tests for the shipped device model built before the Config facade is
 * bootstrapped, as a data provider builds one: it takes the default table and
 * the default connection rather than failing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Device::class)]
final class DeviceWithoutApplicationTest extends TestCase
{
    /**
     * Unset the facade application, so no facade has a root.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
    }

    /**
     * The model takes the `devices` table on the default connection.
     *
     * @return void
     */
    public function testTakesTheDefaultTableAndConnection(): void
    {
        $device = new Device;

        self::assertSame('devices', $device->getTable());
        self::assertNull($device->getConnectionName());
    }
}
