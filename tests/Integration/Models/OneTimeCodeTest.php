<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Integration tests for the one-time code model: its table and connection, what
 * it keeps out of serialisation, and pruning expired codes with Laravel's
 * `model:prune`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCode::class)]
final class OneTimeCodeTest extends TestCase
{
    /**
     * Release the clock, and restore the configured table so the shipped one is
     * dropped with the others.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        config()->set('authentication.codes.table', 'one_time_codes');

        parent::tearDown();
    }

    /**
     * The model reads the configured table, on the storage connection, each
     * time one is made, whatever connection the device model names.
     *
     * @return void
     */
    public function testUsesTheConfiguredTableOnTheStorageConnection(): void
    {
        self::assertSame('one_time_codes', (new OneTimeCode)->getTable());

        config()->set('authentication.codes.table', 'sign_in_codes');

        self::assertSame('sign_in_codes', (new OneTimeCode)->getTable());

        config()->set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertNull((new OneTimeCode)->getConnectionName());

        config()->set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', (new OneTimeCode)->getConnectionName());

        config()->set('authentication.storage.connection', '');

        self::assertNull((new OneTimeCode)->getConnectionName());
    }

    /**
     * The binding digest, the issuance and the code's hash never reach a
     * serialised row, and the times are cast.
     *
     * @return void
     */
    public function testKeepsTheDigestsOutOfSerialisation(): void
    {
        self::insertCode('a', '2026-04-06 12:10:00');

        $code = OneTimeCode::query()->sole();

        self::assertSame(['purpose', 'guard', 'attempts', 'issued_at', 'expires_at', 'consumed_at'], array_keys($code->toArray()));
        self::assertSame(3, $code->attempts);
        self::assertSame('2026-04-06 12:10:00', $code->expires_at->format('Y-m-d H:i:s'));
        self::assertNull($code->consumed_at);
    }

    /**
     * `model:prune` deletes the codes that have expired, from the second they
     * expire, and keeps the rest.
     *
     * @return void
     */
    public function testPrunesExpiredCodes(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-04-06 12:00:00'));

        self::insertCode('a', '2026-04-06 11:00:00');
        self::insertCode('b', '2026-04-06 12:00:00');
        self::insertCode('c', '2026-04-06 12:00:01');

        Artisan::call('model:prune', ['--model' => [OneTimeCode::class]]);

        self::assertSame([str_repeat('c', 64)], DB::table('one_time_codes')->pluck('id')->all());
    }

    /**
     * Insert a code row keyed by the repeated character, expiring at the time.
     *
     * @param  string  $key
     * @param  string  $expiresAt
     * @return void
     */
    private static function insertCode(string $key, string $expiresAt): void
    {
        self::assertTrue(Schema::hasTable('one_time_codes'));

        DB::table('one_time_codes')->insert([
            'id'         => str_repeat($key, 64),
            'purpose'    => 'sign_in',
            'guard'      => 'mobile',
            'issue_id'   => '0195f4a2-7b1c-4000-8000-00000000000' . $key,
            'code_hash'  => str_repeat('f', 64),
            'attempts'   => 3,
            'issued_at'  => '2026-04-06 11:00:00',
            'expires_at' => $expiresAt,
        ]);
    }
}
