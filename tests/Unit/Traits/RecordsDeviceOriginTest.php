<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\RecordsDeviceOrigin;
use Tests\Unit\Stubs\StubDevice;

/**
 * Unit tests for the accessors behind what a device's session started with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(RecordsDeviceOrigin::class)]
final class RecordsDeviceOriginTest extends TestCase
{
    /**
     * The guard and sign-in method read the recorded values as strings.
     *
     * @return void
     */
    public function testReadsTheRecordedGuardAndMethod(): void
    {
        $device = (new StubDevice)->forceFill(['guard' => 'api', 'sign_in_method' => 'password']);

        self::assertSame('api', $device->getGuard());
        self::assertSame('password', $device->getSignInMethod());
    }

    /**
     * Informational values that were never recorded, or not loaded, read as
     * `null` rather than failing.
     *
     * @return void
     */
    public function testValuesNotRecordedOrNotLoadedReadAsNull(): void
    {
        $recordedNull = (new StubDevice)->forceFill(['guard' => null, 'sign_in_method' => null]);
        $notLoaded    = new StubDevice;

        self::assertNull($recordedNull->getGuard());
        self::assertNull($recordedNull->getSignInMethod());
        self::assertNull($notLoaded->getGuard());
        self::assertNull($notLoaded->getSignInMethod());
    }

    /**
     * The column names are the shipped migration's.
     *
     * @return void
     */
    public function testNamesTheShippedColumns(): void
    {
        $device = new StubDevice;

        self::assertSame('guard', $device->getGuardName());
        self::assertSame('sign_in_method', $device->getSignInMethodName());
        self::assertSame('client_name', $device->getClientNameName());
        self::assertSame('platform', $device->getPlatformName());
        self::assertSame('created_ip', $device->getCreatedIpName());
        self::assertSame('created_user_agent', $device->getCreatedUserAgentName());
    }
}
