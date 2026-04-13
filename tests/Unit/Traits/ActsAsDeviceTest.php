<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsDevice;

/**
 * Unit tests for the package ActsAsDevice trait.
 *
 * Exercises the trait through an anonymous Eloquent model because the trait is
 * defined against Eloquent's `getAttribute` accessor contract, without relying
 * on explicit PHPUnit coverage metadata for traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ActsAsDeviceTest extends TestCase
{
    /** @var \Carbon\Carbon Frozen clock reference shared across timestamp assertions. */
    private Carbon $now;

    /**
     * Freeze the clock so Carbon timestamp assertions are deterministic.
     *
     * @return void
     */
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
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Asserts the device identifier getter reads the model's `id` attribute
     * when no attribute-name override is supplied.
     *
     * @return void
     */
    public function testGetDeviceIdentifierReturnsIdAttribute(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var bool Indicates whether the IDs are auto-incrementing. */
            public $incrementing = false;

            /** @var string The "type" of the primary key ID. */
            protected $keyType = 'string';

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['id' => 'device-123']);

        self::assertSame('device-123', $device->getDeviceIdentifier());
    }

    /**
     * Asserts the last-logged-in getter returns the Carbon instance stored in
     * the attribute, and null when the attribute is null.
     *
     * @return void
     */
    public function testGetLastLoggedInReturnsCarbonInstanceOrNull(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['last_logged_in_at' => $this->now]);

        self::assertSame($this->now, $device->getLastLoggedIn());

        $device->setRawAttributes(['last_logged_in_at' => null]);

        self::assertNull($device->getLastLoggedIn());
    }

    /**
     * Asserts the MFA verification getter returns the Carbon instance stored in
     * the attribute, and null when the attribute is null.
     *
     * @return void
     */
    public function testGetLastMfaVerificationReturnsCarbonInstanceOrNull(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['last_mfa_verified_at' => $this->now]);

        self::assertSame($this->now, $device->getLastMfaVerification());

        $device->setRawAttributes(['last_mfa_verified_at' => null]);

        self::assertNull($device->getLastMfaVerification());
    }

    /**
     * Asserts the operating system getter casts the underlying attribute to a
     * string before returning it.
     *
     * @return void
     */
    public function testGetOperatingSystemCastsToString(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['os' => 'iOS 18.4']);

        self::assertSame('iOS 18.4', $device->getOperatingSystem());
    }

    /**
     * Asserts the operating system getter coerces a non-string attribute (e.g.
     * an integer column) into its string form rather than returning the raw
     * value or `null`.
     *
     * @return void
     */
    public function testGetOperatingSystemCoercesIntegerToString(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['os' => 1]);

        self::assertSame('1', $device->getOperatingSystem());
    }

    /**
     * Asserts the refresh-key getter casts the underlying attribute to a string
     * before returning it.
     *
     * @return void
     */
    public function testGetRefreshKeyCastsToString(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['refresh_key' => 'hashed-refresh-key']);

        self::assertSame('hashed-refresh-key', $device->getRefreshKey());
    }

    /**
     * Asserts the refresh-key getter returns `null` when the underlying
     * attribute is null - the device row carries no refresh credential.
     *
     * @return void
     */
    public function testGetRefreshKeyReturnsNullWhenAttributeNull(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['refresh_key' => null]);

        self::assertNull($device->getRefreshKey());
    }

    /**
     * Asserts the revoked-at getter returns the Carbon instance when present
     * and null when the attribute is null.
     *
     * @return void
     */
    public function testGetRevokedAtReturnsCarbonInstanceOrNull(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $device->setRawAttributes(['revoked_at' => $this->now]);
        self::assertSame($this->now, $device->getRevokedAt());

        $device->setRawAttributes(['revoked_at' => null]);
        self::assertNull($device->getRevokedAt());
    }

    /**
     * Asserts the public column-name accessors return the documented defaults
     * so consumer listeners (e.g. `UpdateDeviceTimestamp`) and the
     * refresh-token exchange resolve the correct columns without reflection.
     * Pinning the default values defends against accidental rename mutations
     * of the trait constants.
     *
     * @return void
     */
    public function testColumnNameAccessorsExposeDocumentedDefaults(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        self::assertSame('id', $device->getDeviceIdentifierName());
        self::assertSame('last_logged_in_at', $device->getLastLoggedInName());
        self::assertSame('last_mfa_verified_at', $device->getLastMfaVerificationName());
        self::assertSame('os', $device->getOperatingSystemName());
        self::assertSame('refresh_key', $device->getRefreshKeyName());
        self::assertSame('revoked_at', $device->getRevokedAtName());
    }

    /**
     * Asserts a subclass can override the protected attribute-name hooks to
     * source values from non-default columns.
     *
     * @return void
     */
    public function testAttributeNamesCanBeOverridden(): void
    {
        $device = new class extends Model {
            use ActsAsDevice;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];

            /**
             * Get device identifier name.
             *
             * @return string
             */
            protected function getDeviceIdentifierName(): string
            {
                return 'device_uuid';
            }
        };

        $device->setRawAttributes([
            'device_uuid' => 'uuid-from-override',
        ]);

        self::assertSame('uuid-from-override', $device->getDeviceIdentifier());
    }
}
