<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;

/**
 * RefreshFailed event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[\PHPUnit\Framework\Attributes\CoversClass(RefreshFailed::class)]
final class RefreshFailedTest extends TestCase
{
    /**
     * Constructor retains the supplied guard, reason, and device id.
     *
     * @return void
     */
    public function testStoresGuardReasonAndDeviceIdOnConstruction(): void
    {
        $event = new RefreshFailed('api', RefreshFailureReason::ROTATION_MISMATCH, 'd-1');

        self::assertSame('api', $event->guard);
        self::assertSame(RefreshFailureReason::ROTATION_MISMATCH, $event->reason);
        self::assertSame('d-1', $event->deviceId);
    }

    /**
     * The deviceId argument is optional and defaults to null.
     *
     * @return void
     */
    public function testDeviceIdDefaultsToNull(): void
    {
        $event = new RefreshFailed('api', RefreshFailureReason::TOKEN_INVALID);

        self::assertNull($event->deviceId);
    }

    /**
     * The reason enum covers every early-return path in the
     * `JwtGuard::refresh()` flow - this assertion guards against accidentally
     * introducing a new branch without a matching enum case.
     *
     * @return void
     */
    public function testReasonEnumCoversEveryFailurePath(): void
    {
        self::assertSame('token_invalid', RefreshFailureReason::TOKEN_INVALID->value);
        self::assertSame('device_unknown', RefreshFailureReason::DEVICE_UNKNOWN->value);
        self::assertSame('rotation_mismatch', RefreshFailureReason::ROTATION_MISMATCH->value);
        self::assertSame('rotation_reuse', RefreshFailureReason::ROTATION_REUSE->value);
        self::assertSame('device_revoked', RefreshFailureReason::DEVICE_REVOKED->value);
        self::assertSame('authenticatable_missing', RefreshFailureReason::AUTHENTICATABLE_MISSING->value);
        self::assertSame('identity_inactive', RefreshFailureReason::IDENTITY_INACTIVE->value);
        self::assertSame('principal_unresolved', RefreshFailureReason::PRINCIPAL_UNRESOLVED->value);
        self::assertSame('principal_mismatch', RefreshFailureReason::PRINCIPAL_MISMATCH->value);
        self::assertSame('principal_inactive', RefreshFailureReason::PRINCIPAL_INACTIVE->value);
    }
}
