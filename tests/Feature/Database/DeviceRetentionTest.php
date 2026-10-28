<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\DeviceRetention;
use Tests\TestCase;

/**
 * Feature tests for the device retention pruning and `authentication:check`
 * both read: 30 days unless configured, the boundaries accepted, and anything
 * else refused with the same message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRetention::class)]
final class DeviceRetentionTest extends TestCase
{
    /**
     * With nothing configured the retention is 30 days.
     *
     * @return void
     */
    public function testDefaultsToThirtyDays(): void
    {
        config()->set('authentication.device', ['model' => 'unused']);

        self::assertSame(30, DeviceRetention::days());
    }

    /**
     * The boundaries are accepted, as integers and as the digit strings `env()`
     * returns, and read when asked.
     *
     * @return void
     */
    public function testReadsTheBoundariesWhenAsked(): void
    {
        config()->set('authentication.device.prune_after_days', '0');

        self::assertSame(0, DeviceRetention::days());

        config()->set('authentication.device.prune_after_days', 3650);

        self::assertSame(3650, DeviceRetention::days());
    }

    /**
     * A retention past the boundaries is refused.
     *
     * @return void
     */
    public function testRefusesARetentionPastTheBoundaries(): void
    {
        config()->set('authentication.device.prune_after_days', '3651');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.device.prune_after_days` must be an integer from 0 to 3650 days.');

        DeviceRetention::days();
    }

    /**
     * `DeviceRetention` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DeviceRetention::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
