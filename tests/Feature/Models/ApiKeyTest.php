<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for the API key model: its configured table on the device
 * model's connection, what it hides and casts, and pruning keys revoked or
 * expired longer ago than the retention.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKey::class)]
final class ApiKeyTest extends TestCase
{
    /**
     * Release the clock and drop the shipped table, whatever table name a test
     * left configured.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Schema::dropIfExists('api_keys');

        parent::tearDown();
    }

    /**
     * The model reads its table from the configuration and follows the device
     * model onto its connection, each time it is built.
     *
     * @return void
     */
    public function testUsesTheConfiguredTableOnTheDeviceConnection(): void
    {
        self::assertSame('api_keys', (new ApiKey)->getTable());
        self::assertNull((new ApiKey)->getConnectionName());

        Config::set('authentication.api_keys.table', 'machine_keys');
        Config::set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertSame('machine_keys', (new ApiKey)->getTable());
        self::assertSame(SeparateConnectionDevice::CONNECTION, (new ApiKey)->getConnectionName());
    }

    /**
     * A key is keyed by a string id, casts its scopes and times, accepts no
     * mass assignment and never serialises the digest of its secret.
     *
     * @return void
     */
    public function testHidesTheSecretDigestAndCastsItsColumns(): void
    {
        DB::table('api_keys')->insert([
            'id'                   => '0195f4a2-7b1c-7000-8000-000000000001',
            'public_id'            => 'ak_abcdefghijklmnop',
            'secret_hash'          => str_repeat('a', 64),
            'guard'                => 'machine',
            'authenticatable_type' => 'machine',
            'authenticatable_id'   => '1',
            'principal_type'       => 'machine',
            'principal_id'         => '1',
            'scopes'               => '["read","write"]',
            'expires_at'           => '2027-01-15 10:00:00',
            'last_used_at'         => '2027-01-14 10:00:00',
            'rotated_at'           => '2027-01-13 10:00:00',
            'revoked_at'           => '2027-01-12 10:00:00',
        ]);

        $key = ApiKey::query()->sole();

        self::assertSame(['read', 'write'], $key->scopes);
        self::assertSame('2027-01-15 10:00:00', $key->expires_at?->format('Y-m-d H:i:s'));
        self::assertSame('2027-01-14 10:00:00', $key->last_used_at?->format('Y-m-d H:i:s'));
        self::assertSame('2027-01-13 10:00:00', $key->rotated_at?->format('Y-m-d H:i:s'));
        self::assertSame('2027-01-12 10:00:00', $key->revoked_at?->format('Y-m-d H:i:s'));
        self::assertArrayNotHasKey('secret_hash', $key->toArray());
        self::assertStringNotContainsString(str_repeat('a', 64), $key->toJson());
        self::assertFalse($key->getIncrementing());
        self::assertSame('string', $key->getKeyType());
        self::assertFalse((new ApiKey)->isFillable('guard'));
    }

    /**
     * `model:prune` deletes keys revoked or expired at or before the retention
     * ago, and keeps live keys and those that ended more recently.
     *
     * @return void
     */
    public function testPruningDeletesKeysThatEndedLongerAgoThanTheRetention(): void
    {
        Carbon::setTestNow(Carbon::parse('2027-02-14 10:00:00'));

        Config::set('authentication.api_keys.prune_after_days', '30');

        $rows = [
            'revoked long ago' => ['revoked_at' => '2027-01-15 10:00:00', 'expires_at' => null],
            'revoked recently' => ['revoked_at' => '2027-01-15 10:00:01', 'expires_at' => null],
            'expired long ago' => ['revoked_at' => null, 'expires_at' => '2027-01-15 10:00:00'],
            'expired recently' => ['revoked_at' => null, 'expires_at' => '2027-01-15 10:00:01'],
            'live, expiring'   => ['revoked_at' => null, 'expires_at' => '2027-03-01 10:00:00'],
            'live, never'      => ['revoked_at' => null, 'expires_at' => null],
        ];

        $number = 0;

        foreach ($rows as $name => $times) {

            $number++;

            DB::table('api_keys')->insert($times + [
                'id'                   => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
                'public_id'            => 'ak_' . str_pad((string) $number, 16, '0', STR_PAD_LEFT),
                'secret_hash'          => str_repeat('a', 64),
                'guard'                => 'machine',
                'name'                 => $name,
                'authenticatable_type' => 'machine',
                'authenticatable_id'   => '1',
                'principal_type'       => 'machine',
                'principal_id'         => '1',
                'scopes'               => '[]',
            ]);
        }

        Artisan::call('model:prune', ['--model' => [ApiKey::class]]);

        self::assertEqualsCanonicalizing(['revoked recently', 'expired recently', 'live, expiring', 'live, never'], DB::table('api_keys')->pluck('name')->all());
    }

    /**
     * A retention out of range fails pruning closed.
     *
     * @return void
     */
    public function testARetentionOutOfRangeFailsPruningClosed(): void
    {
        Config::set('authentication.api_keys.prune_after_days', 3651);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.api_keys.prune_after_days` must be an integer from 0 to 3650 days.');

        (new ApiKey)->prunable();
    }
}
