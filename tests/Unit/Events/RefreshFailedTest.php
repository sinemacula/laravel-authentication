<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
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
        $event = new RefreshFailed('api', RefreshFailureReason::ROTATION_REUSE, 'd-1');

        self::assertSame('api', $event->guard);
        self::assertSame(RefreshFailureReason::ROTATION_REUSE, $event->reason);
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
        self::assertSame([
            'token_invalid',
            'device_unknown',
            'rotation_reuse',
            'rotation_conflict',
            'refresh_key_missing',
            'device_revoked',
            'session_expired',
            'authenticatable_missing',
            'identity_inactive',
            'principal_unresolved',
            'principal_mismatch',
            'principal_inactive',
            'tenant_inactive',
        ], array_map(static fn (RefreshFailureReason $reason): string => $reason->value, RefreshFailureReason::cases()));
    }
}
