<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for where the pending sign-in model keeps its rows: the
 * configured table, on the device model's connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSignIn::class)]
final class PendingSignInTest extends TestCase
{
    /**
     * The model uses the configured table, and `pending_sign_ins` when none is
     * configured.
     *
     * @return void
     */
    public function testTheTableIsTheConfiguredOne(): void
    {
        Config::set('authentication.sign_in.pending_table', 'factor_waits');

        self::assertSame('factor_waits', (new PendingSignIn)->getTable());

        Config::set('authentication.sign_in', []);

        self::assertSame('pending_sign_ins', (new PendingSignIn)->getTable());
    }

    /**
     * The model follows the device model onto its connection, so a pending
     * sign-in and the device it may continue live on the same one.
     *
     * @return void
     */
    public function testTheConnectionIsTheDeviceModelsOne(): void
    {
        Config::set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertSame(SeparateConnectionDevice::CONNECTION, (new PendingSignIn)->getConnectionName());

        Config::set('authentication.device.model', Device::class);

        self::assertNull((new PendingSignIn)->getConnectionName());
    }
}
