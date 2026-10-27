<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\DeviceSummary;
use Tests\Unit\Stubs\StubUncastDevice;

/**
 * Unit tests for the summary a device list shows of one device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceSummary::class)]
final class DeviceSummaryTest extends TestCase
{
    /** @var array<string, mixed> Every column a device row stores, with stored values. */
    private const array ROW = [
        'id'                    => 'device-1',
        'authenticatable_type'  => 'users',
        'authenticatable_id'    => '7',
        'principal_type'        => 'members',
        'principal_id'          => '9',
        'guard'                 => 'api',
        'sign_in_method'        => 'password',
        'client_name'           => 'Phone',
        'platform'              => 'iOS',
        'created_ip'            => '198.51.100.1',
        'created_user_agent'    => 'Created/1.0',
        'last_used_at'          => '2027-01-15 09:59:00',
        'last_used_ip'          => '198.51.100.2',
        'last_used_user_agent'  => 'Used/1.0',
        'refresh_key'           => 'current-digest',
        'previous_refresh_key'  => 'previous-digest',
        'refresh_rotated_at'    => '2027-01-15 09:00:00',
        'idle_expires_at'       => '2027-02-14 10:00:00',
        'absolute_expires_at'   => '2027-03-16 10:00:00',
        'revoked_at'            => null,
        'revoked_reason'        => null,
        'signed_in_at'          => '2027-01-15 08:00:00',
        'principal_switched_at' => null,
        'created_at'            => '2027-01-14 10:00:00',
        'updated_at'            => '2027-01-15 09:59:00',
    ];

    /**
     * Every field comes from the row, and the times are immutable.
     *
     * @return void
     */
    public function testSummarisesEveryColumnItShows(): void
    {
        $summary = DeviceSummary::of(self::device(self::ROW), true);

        self::assertSame('device-1', $summary->id);
        self::assertSame('api', $summary->guard);
        self::assertSame('password', $summary->signInMethod);
        self::assertSame('Phone', $summary->clientName);
        self::assertSame('iOS', $summary->platform);
        self::assertSame('198.51.100.1', $summary->createdIp);
        self::assertSame('Created/1.0', $summary->createdUserAgent);
        self::assertSame('198.51.100.2', $summary->lastUsedIp);
        self::assertSame('Used/1.0', $summary->lastUsedUserAgent);
        self::assertTrue($summary->current);
        self::assertInstanceOf(CarbonImmutable::class, $summary->createdAt);
        self::assertInstanceOf(CarbonImmutable::class, $summary->lastUsedAt);
        self::assertSame('2027-01-14 10:00:00', $summary->createdAt->format('Y-m-d H:i:s'));
        self::assertSame('2027-01-15 09:59:00', $summary->lastUsedAt->format('Y-m-d H:i:s'));
        self::assertSame('2027-01-15 08:00:00', $summary->signedInAt->format('Y-m-d H:i:s'));
        self::assertSame('2027-02-14 10:00:00', $summary->idleExpiresAt->format('Y-m-d H:i:s'));
        self::assertSame('2027-03-16 10:00:00', $summary->absoluteExpiresAt->format('Y-m-d H:i:s'));
    }

    /**
     * The array and JSON forms use snake_case keys and ISO-8601 times, and hold
     * nothing of the digests, the rotation, the revocation, the owner or the
     * principal.
     *
     * @return void
     */
    public function testArrayAndJsonHoldOnlyTheSafeFields(): void
    {
        $summary  = DeviceSummary::of(self::device(self::ROW), false);
        $expected = [
            'id'                   => 'device-1',
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'client_name'          => 'Phone',
            'platform'             => 'iOS',
            'created_at'           => '2027-01-14T10:00:00+00:00',
            'created_ip'           => '198.51.100.1',
            'created_user_agent'   => 'Created/1.0',
            'signed_in_at'         => '2027-01-15T08:00:00+00:00',
            'last_used_at'         => '2027-01-15T09:59:00+00:00',
            'last_used_ip'         => '198.51.100.2',
            'last_used_user_agent' => 'Used/1.0',
            'idle_expires_at'      => '2027-02-14T10:00:00+00:00',
            'absolute_expires_at'  => '2027-03-16T10:00:00+00:00',
            'current'              => false,
        ];

        self::assertSame($expected, $summary->toArray());
        self::assertSame($expected, $summary->jsonSerialize());

        $json = (string) json_encode($summary);

        foreach (['digest', 'refresh', 'revoked', 'authenticatable', 'principal', 'members', 'updated_at', 'switched'] as $hidden) {
            self::assertStringNotContainsString($hidden, $json);
        }
    }

    /**
     * Informational columns that are null, not loaded, or not text read as
     * `null`, as do the creation and last-use times.
     *
     * @return void
     */
    public function testAbsentOrUnreadableColumnsReadAsNull(): void
    {
        $row = self::ROW;

        unset($row['client_name'], $row['created_at'], $row['guard']);

        $row['platform']     = ['not', 'text'];
        $row['last_used_at'] = null;
        $row['created_ip']   = null;

        $summary = DeviceSummary::of(self::device($row), false);

        self::assertNull($summary->clientName);
        self::assertNull($summary->platform);
        self::assertNull($summary->createdAt);
        self::assertNull($summary->createdIp);
        self::assertNull($summary->lastUsedAt);
        self::assertNull($summary->guard);
        self::assertNull($summary->toArray()['created_at']);
        self::assertNull($summary->toArray()['last_used_at']);
    }

    /**
     * A scalar column that is not a string reads as its text.
     *
     * @return void
     */
    public function testScalarColumnsReadAsText(): void
    {
        $row = self::ROW;

        $row['client_name'] = 42;

        self::assertSame('42', DeviceSummary::of(self::device($row), false)->clientName);
    }

    /**
     * A model that names no creation column has no creation time.
     *
     * @return void
     */
    public function testAModelWithoutACreationColumnHasNoCreationTime(): void
    {
        $device = new class extends StubUncastDevice {
            /** @var null The name of the "created at" column: none. */
            public const null CREATED_AT = null;
        };

        $device->setRawAttributes(self::ROW);

        self::assertNull(DeviceSummary::of($device, false)->createdAt);
    }

    /**
     * Columns that are not loaded read as `null` without asking the model for
     * them, so a model that prevents accessing missing attributes is still
     * summarised.
     *
     * @return void
     */
    public function testColumnsThatAreNotLoadedAreNeverAskedFor(): void
    {
        $row = self::ROW;

        unset($row['client_name'], $row['platform'], $row['created_at'], $row['created_ip'], $row['last_used_ip']);

        Model::preventAccessingMissingAttributes();

        try {
            $summary = DeviceSummary::of(self::device($row), false);
        } finally {
            Model::preventAccessingMissingAttributes(false);
        }

        self::assertNull($summary->clientName);
        self::assertNull($summary->platform);
        self::assertNull($summary->createdAt);
        self::assertNull($summary->createdIp);
        self::assertNull($summary->lastUsedIp);
        self::assertSame('Created/1.0', $summary->createdUserAgent);
    }

    /**
     * A device without a deadline or a sign-in time cannot be summarised: an
     * active device always has them.
     *
     * @return void
     */
    public function testRefusesADeviceWithoutADeadline(): void
    {
        $unsigned = self::ROW;

        $unsigned['signed_in_at'] = null;

        try {
            DeviceSummary::of(self::device($unsigned), false);
            self::fail('A device without a sign-in time was summarised.');
        } catch (\LogicException $exception) {
            self::assertSame('Device device-1 of ' . StubUncastDevice::class . ' has no sign-in time to summarise.', $exception->getMessage());
        }

        $row = self::ROW;

        $row['absolute_expires_at'] = null;

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Device device-1 of ' . StubUncastDevice::class . ' has no session deadline to summarise.');

        DeviceSummary::of(self::device($row), false);
    }

    /**
     * A device holding the given raw row.
     *
     * @param  array<string, mixed>  $row
     * @return \Tests\Unit\Stubs\StubUncastDevice
     */
    private static function device(array $row): StubUncastDevice
    {
        $device = new StubUncastDevice;

        $device->setKeyType('string');
        $device->setRawAttributes($row);

        return $device;
    }
}
