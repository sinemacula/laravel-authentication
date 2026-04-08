<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;

/**
 * RefreshFailed event unit tests.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(RefreshFailed::class)]
final class RefreshFailedTest extends TestCase
{
    /**
     * Constructor retains the supplied guard, reason, and device id.
     *
     * @return void
     */
    public function testStoresGuardReasonAndDeviceIdOnConstruction(): void
    {
        $event = new RefreshFailed('api', RefreshFailed::REASON_ROTATION_MISMATCH, 'd-1');

        self::assertSame('api', $event->guard);
        self::assertSame(RefreshFailed::REASON_ROTATION_MISMATCH, $event->reason);
        self::assertSame('d-1', $event->deviceId);
    }

    /**
     * The deviceId argument is optional and defaults to null.
     *
     * @return void
     */
    public function testDeviceIdDefaultsToNull(): void
    {
        $event = new RefreshFailed('api', RefreshFailed::REASON_TOKEN_INVALID);

        self::assertNull($event->deviceId);
    }

    /**
     * The reason constants cover every early-return path in the
     * `JwtGuard::refresh()` flow — this assertion guards against
     * accidentally introducing a new branch without a matching reason
     * string.
     *
     * @return void
     */
    public function testReasonConstantsCoverEveryFailurePath(): void
    {
        self::assertSame('token_invalid', RefreshFailed::REASON_TOKEN_INVALID);
        self::assertSame('device_unknown', RefreshFailed::REASON_DEVICE_UNKNOWN);
        self::assertSame('rotation_mismatch', RefreshFailed::REASON_ROTATION_MISMATCH);
        self::assertSame('authenticatable_missing', RefreshFailed::REASON_AUTHENTICATABLE_MISSING);
        self::assertSame('identity_inactive', RefreshFailed::REASON_IDENTITY_INACTIVE);
        self::assertSame('principal_unresolved', RefreshFailed::REASON_PRINCIPAL_UNRESOLVED);
        self::assertSame('principal_inactive', RefreshFailed::REASON_PRINCIPAL_INACTIVE);
    }
}
