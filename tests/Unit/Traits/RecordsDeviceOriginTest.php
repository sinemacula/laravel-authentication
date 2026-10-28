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
     * The guard, the sign-in method and the type of identifier it used read the
     * recorded values as strings.
     *
     * @return void
     */
    public function testReadsTheRecordedGuardAndMethod(): void
    {
        $device = (new StubDevice)->forceFill(['guard' => 'api', 'sign_in_method' => 'password', 'sign_in_identifier_type' => 'email']);

        self::assertSame('api', $device->getGuard());
        self::assertSame('password', $device->getSignInMethod());
        self::assertSame('email', $device->getSignInIdentifierType());
    }

    /**
     * Values that were never recorded read as `null`, and the guard and the
     * method read so when not loaded too, rather than failing.
     *
     * @return void
     */
    public function testValuesNotRecordedOrNotLoadedReadAsNull(): void
    {
        $recordedNull = (new StubDevice)->forceFill(['guard' => null, 'sign_in_method' => null, 'sign_in_identifier_type' => null]);
        $notLoaded    = new StubDevice;

        self::assertNull($recordedNull->getGuard());
        self::assertNull($recordedNull->getSignInMethod());
        self::assertNull($recordedNull->getSignInIdentifierType());
        self::assertNull($notLoaded->getGuard());
        self::assertNull($notLoaded->getSignInMethod());
    }

    /**
     * The identifier type a switch is held to is reported when it was not
     * loaded, rather than read as a sign-in that used no identifier.
     *
     * @return void
     */
    public function testAnIdentifierTypeNotLoadedIsReported(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot read the device state of ' . StubDevice::class . ': its `sign_in_identifier_type` attribute is not loaded.'
            . ' Select the column or override getSignInIdentifierType().',
        );

        (new StubDevice)->forceFill(['guard' => 'api', 'sign_in_method' => 'password'])->getSignInIdentifierType();
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
        self::assertSame('sign_in_identifier_type', $device->getSignInIdentifierTypeName());
        self::assertSame('client_name', $device->getClientNameName());
        self::assertSame('platform', $device->getPlatformName());
        self::assertSame('created_ip', $device->getCreatedIpName());
        self::assertSame('created_user_agent', $device->getCreatedUserAgentName());
    }
}
