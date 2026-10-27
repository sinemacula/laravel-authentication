<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use Tests\Unit\Stubs\StubUncastDevice;

/**
 * Unit tests for the package ActsAsDevice trait.
 *
 * Exercises the trait through a cast-free Eloquent device, and anonymous
 * subclasses of it, because the trait is defined against Eloquent's attribute
 * accessors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsDevice::class)]
final class ActsAsDeviceTest extends TestCase
{
    /** @var \Carbon\Carbon Frozen clock reference shared across timestamp assertions. */
    private Carbon $now;

    /**
     * Freeze the clock so Carbon timestamp assertions are deterministic.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
    }

    /**
     * Release the frozen clock once each test has completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The device identifier is the primary key, whatever the key column is
     * called.
     *
     * @return void
     */
    public function testGetDeviceIdentifierReturnsThePrimaryKey(): void
    {
        $device = new class extends StubUncastDevice {
            /** @var string The primary key for the model. */
            protected $primaryKey = 'uuid';

            /** @var string The "type" of the primary key ID. */
            protected $keyType = 'string';
        };

        $device->setRawAttributes(['uuid' => 'device-123', 'id' => 'not-the-key']);

        self::assertSame('device-123', $device->getDeviceIdentifier());
    }

    /**
     * Rows of `[getter, column]` for the timestamp getters, every one of which
     * converts a raw stored value.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed, 1: string}>
     */
    public static function provideTimestampGetters(): iterable
    {
        yield from [
            'last use'        => [static fn (StubUncastDevice $device): mixed => $device->getLastUsedAt(), 'last_used_at'],
            'rotation time'   => [static fn (StubUncastDevice $device): mixed => $device->getRefreshRotatedAt(), 'refresh_rotated_at'],
            'idle deadline'   => [static fn (StubUncastDevice $device): mixed => $device->getIdleExpiresAt(), 'idle_expires_at'],
            'absolute'        => [static fn (StubUncastDevice $device): mixed => $device->getAbsoluteExpiresAt(), 'absolute_expires_at'],
            'revocation time' => [static fn (StubUncastDevice $device): mixed => $device->getRevokedAt(), 'revoked_at'],
        ];
    }

    /**
     * A stored timestamp is returned as the Carbon instance the cast produced,
     * and a stored `null` as `null`.
     *
     * @param  \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed  $getter
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideTimestampGetters')]
    public function testTimestampGetterReturnsTheStoredInstanceOrNull(\Closure $getter, string $column): void
    {
        $device = new StubUncastDevice;
        $stored = CarbonImmutable::instance($this->now);

        $device->setRawAttributes([$column => $stored]);

        self::assertSame($stored, $getter($device));

        $device->setRawAttributes([$column => null]);

        self::assertNull($getter($device));
    }

    /**
     * A timestamp stored without a `datetime` cast (the raw value the database
     * returns, as a string or a Unix timestamp) is converted to a Carbon
     * instance rather than read as `null`.
     *
     * @param  \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed  $getter
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideTimestampGetters')]
    public function testTimestampGetterConvertsAnUncastStoredValue(\Closure $getter, string $column): void
    {
        $device = new StubUncastDevice;

        foreach (['2026-04-06 12:00:00', $this->now->getTimestamp()] as $stored) {

            $device->setRawAttributes([$column => $stored]);

            $converted = $getter($device);

            self::assertInstanceOf(CarbonInterface::class, $converted);
            self::assertSame($this->now->getTimestamp(), $converted->getTimestamp());
        }
    }

    /**
     * Rows of `[getter, column]` for the string getters.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed, 1: string}>
     */
    public static function provideStringGetters(): iterable
    {
        yield from [
            'current digest'    => [static fn (StubUncastDevice $device): mixed => $device->getRefreshKey(), 'refresh_key'],
            'previous digest'   => [static fn (StubUncastDevice $device): mixed => $device->getPreviousRefreshKey(), 'previous_refresh_key'],
            'revocation reason' => [static fn (StubUncastDevice $device): mixed => $device->getRevokedReason(), 'revoked_reason'],
        ];
    }

    /**
     * A string column is returned as a string, a stored `null` as `null`, and a
     * non-string stored value is converted.
     *
     * @param  \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed  $getter
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideStringGetters')]
    public function testStringGetterReturnsTheStoredStringOrNull(\Closure $getter, string $column): void
    {
        $device = new StubUncastDevice;

        $device->setRawAttributes([$column => 'stored-value']);

        self::assertSame('stored-value', $getter($device));

        $device->setRawAttributes([$column => 1]);

        self::assertSame('1', $getter($device));

        $device->setRawAttributes([$column => null]);

        self::assertNull($getter($device));
    }

    /**
     * Rows of `[getter, column, column-name accessor]` for the refresh and
     * revocation state getters, which must find their attribute loaded.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed, 1: string, 2: string}>
     */
    public static function provideStateGetters(): iterable
    {
        yield from [
            'current digest'  => [static fn (StubUncastDevice $device): mixed => $device->getRefreshKey(), 'refresh_key', 'getRefreshKeyName'],
            'previous digest' => [static fn (StubUncastDevice $device): mixed => $device->getPreviousRefreshKey(), 'previous_refresh_key', 'getPreviousRefreshKeyName'],
            'rotation time'   => [static fn (StubUncastDevice $device): mixed => $device->getRefreshRotatedAt(), 'refresh_rotated_at', 'getRefreshRotatedAtName'],
            'idle deadline'   => [static fn (StubUncastDevice $device): mixed => $device->getIdleExpiresAt(), 'idle_expires_at', 'getIdleExpiresAtName'],
            'absolute'        => [static fn (StubUncastDevice $device): mixed => $device->getAbsoluteExpiresAt(), 'absolute_expires_at', 'getAbsoluteExpiresAtName'],
            'revocation time' => [static fn (StubUncastDevice $device): mixed => $device->getRevokedAt(), 'revoked_at', 'getRevokedAtName'],
        ];
    }

    /**
     * A device selected without one of its refresh or revocation state columns
     * is a misconfiguration: the getter throws, naming the model, the column,
     * and the accessor to override, rather than reading the missing value as
     * `null`.
     *
     * @param  \Closure(\Tests\Unit\Stubs\StubUncastDevice): mixed  $getter
     * @param  string  $column
     * @param  string  $accessor
     * @return void
     */
    #[DataProvider('provideStateGetters')]
    public function testStateGetterThrowsWhenItsAttributeIsNotLoaded(\Closure $getter, string $column, string $accessor): void
    {
        $device = new StubUncastDevice;

        $device->setRawAttributes(['id' => 'device-123', 'client_name' => 'iPhone']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot read the device state of ' . $device::class . ": its `{$column}` attribute is not loaded."
            . " Select the column or override {$accessor}().",
        );

        $getter($device);
    }

    /**
     * The last-use time and the revocation reason are informational: a device
     * loaded without either column reads it as `null` instead of throwing.
     *
     * @return void
     */
    public function testInformationalGettersReadAnUnloadedColumnAsNull(): void
    {
        $device = new StubUncastDevice;

        $device->setRawAttributes(['id' => 'device-123']);

        self::assertNull($device->getLastUsedAt());
        self::assertNull($device->getRevokedReason());
    }

    /**
     * A device that renames a state column is checked for that column: the
     * renamed column loaded reads normally without the default one, and the
     * renamed column missing is reported by its own name.
     *
     * @return void
     */
    public function testStateGetterChecksTheOverriddenColumnIsLoaded(): void
    {
        $device = new class extends StubUncastDevice {
            /**
             * Column name holding the idle deadline.
             *
             * @return string
             */
            #[\Override]
            public function getIdleExpiresAtName(): string
            {
                return 'session_idle_until';
            }
        };

        $device->setRawAttributes(['session_idle_until' => $this->now]);

        self::assertSame($this->now, $device->getIdleExpiresAt());

        $device->setRawAttributes(['idle_expires_at' => $this->now]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `session_idle_until` attribute is not loaded');

        $device->getIdleExpiresAt();
    }

    /**
     * The public column-name accessors return the documented defaults, so the
     * last-use listener and the refresh exchange write the columns the shipped
     * migration creates.
     *
     * @return void
     */
    public function testColumnNameAccessorsExposeDocumentedDefaults(): void
    {
        $device = new StubUncastDevice;

        self::assertSame('last_used_at', $device->getLastUsedAtName());
        self::assertSame('last_used_ip', $device->getLastUsedIpName());
        self::assertSame('last_used_user_agent', $device->getLastUsedUserAgentName());
        self::assertSame('refresh_key', $device->getRefreshKeyName());
        self::assertSame('previous_refresh_key', $device->getPreviousRefreshKeyName());
        self::assertSame('refresh_rotated_at', $device->getRefreshRotatedAtName());
        self::assertSame('idle_expires_at', $device->getIdleExpiresAtName());
        self::assertSame('absolute_expires_at', $device->getAbsoluteExpiresAtName());
        self::assertSame('revoked_at', $device->getRevokedAtName());
        self::assertSame('revoked_reason', $device->getRevokedReasonName());
    }

    /**
     * Both refresh digests are left out of `toArray()` and `toJson()`, while
     * the rest of the device, and the model's own hidden attributes, are kept
     * as they were.
     *
     * @return void
     *
     * @throws \Illuminate\Database\Eloquent\JsonEncodingException
     */
    public function testBothDigestsAreHiddenFromSerialisation(): void
    {
        $device = new class extends StubUncastDevice {
            /** @var list<string> The attributes that should be hidden for serialization. */
            protected $hidden = ['created_ip'];
        };

        $device->setRawAttributes([
            'platform'             => 'iOS',
            'client_name'          => 'iPhone',
            'created_ip'           => '203.0.113.7',
            'refresh_key'          => 'current-digest',
            'previous_refresh_key' => 'previous-digest',
        ]);

        self::assertSame(['platform' => 'iOS', 'client_name' => 'iPhone'], $device->toArray());
        self::assertStringNotContainsString('digest', $device->toJson());
    }

    /**
     * A model that renames its digest columns hides them under their own names.
     *
     * @return void
     */
    public function testRenamedDigestColumnsAreHiddenFromSerialisation(): void
    {
        $device = new class extends StubUncastDevice {
            /**
             * Column name holding the digest of the current refresh rotation
             * id.
             *
             * @return string
             */
            #[\Override]
            public function getRefreshKeyName(): string
            {
                return 'current_digest';
            }

            /**
             * Column name holding the digest of the previous refresh rotation
             * id.
             *
             * @return string
             */
            #[\Override]
            public function getPreviousRefreshKeyName(): string
            {
                return 'prior_digest';
            }
        };

        $device->setRawAttributes([
            'platform'       => 'iOS',
            'current_digest' => 'current-digest',
            'prior_digest'   => 'previous-digest',
        ]);

        self::assertSame(['platform' => 'iOS'], $device->toArray());
    }
}
