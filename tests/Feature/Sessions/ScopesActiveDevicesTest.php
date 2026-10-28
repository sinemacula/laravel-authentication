<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ScopesActiveDevices;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;
use Tests\Integration\Fixtures\ScopedRenamedPruningDevice;
use Tests\TestCase;

/**
 * Feature tests for the rule that decides which devices are active, as the
 * `active()` scope and the device list apply it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveDevices::class)]
#[CoversTrait(ScopesActiveDevices::class)]
final class ScopesActiveDevicesTest extends TestCase
{
    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The scope keeps devices that are unrevoked and strictly before both
     * deadlines, with qualified columns, and the current second.
     *
     * @return void
     */
    public function testTheScopeKeepsUnrevokedDevicesBeforeBothDeadlines(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2027-01-15 10:00:00'));

        $query = Device::query()->active();

        self::assertSame(
            'select * from devices where devices.revoked_at is null and devices.idle_expires_at > ? and devices.absolute_expires_at > ?',
            str_replace(['"', '`'], '', $query->toSql()),
        );
        self::assertSame(['2027-01-15 10:00:00', '2027-01-15 10:00:00'], $query->getBindings());
    }

    /**
     * The columns come from the model's name accessors.
     *
     * @return void
     */
    public function testTheColumnsComeFromTheNameAccessors(): void
    {
        $device = new ScopedRenamedPruningDevice;
        $query  = $device->newQueryWithoutScopes();

        ActiveDevices::constrain($query, $device, CarbonImmutable::parse('2027-01-15 10:00:00'));

        self::assertSame(
            'select * from scoped_renamed_pruning_devices where scoped_renamed_pruning_devices.ended_at is null'
                . ' and scoped_renamed_pruning_devices.idle_until > ? and scoped_renamed_pruning_devices.valid_until > ?',
            str_replace(['"', '`'], '', $query->toSql()),
        );
    }

    /**
     * `ActiveDevices` is a static utility; instantiation is disallowed through
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ActiveDevices::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
