<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Integration tests for the pending identifier change model: the table and
 * connection it reads, what its serialised form leaves out, and the pruning of
 * expired changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChange::class)]
final class IdentifierChangeTest extends TestCase
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

        config()->set('authentication.identifier_changes.table', 'identifier_changes');

        parent::tearDown();
    }

    /**
     * The model reads the configured table, on the device model's connection,
     * each time one is made.
     *
     * @return void
     */
    public function testUsesTheConfiguredTableOnTheDeviceModelsConnection(): void
    {
        self::assertSame('identifier_changes', (new IdentifierChange)->getTable());
        self::assertNull((new IdentifierChange)->getConnectionName());

        config()->set('authentication.identifier_changes.table', 'pending_email_changes');
        config()->set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertSame('pending_email_changes', (new IdentifierChange)->getTable());
        self::assertSame((new SeparateConnectionDevice)->getConnectionName(), (new IdentifierChange)->getConnectionName());
    }

    /**
     * The row's digest, both identifiers and the request never reach a
     * serialised row; the times and whether the replaced identifier was
     * verified are cast.
     *
     * @return void
     */
    public function testKeepsTheIdentifiersOutOfSerialisation(): void
    {
        self::insertChange('a', '2026-04-06 13:00:00');

        $change = IdentifierChange::query()->sole();

        self::assertSame(['guard', 'type', 'previous_verified', 'requested_at', 'expires_at'], array_keys($change->toArray()));
        self::assertFalse($change->previous_verified);
        self::assertSame('2026-04-06 13:00:00', $change->expires_at->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-06 12:00:00', $change->requested_at->format('Y-m-d H:i:s'));
    }

    /**
     * `model:prune` deletes the changes that have expired, from the second they
     * expire, and keeps the rest.
     *
     * @return void
     */
    public function testPrunesExpiredChanges(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-04-06 13:00:00'));

        self::insertChange('a', '2026-04-06 12:30:00');
        self::insertChange('b', '2026-04-06 13:00:00');
        self::insertChange('c', '2026-04-06 13:00:01');

        self::assertSame([str_repeat('a', 64), str_repeat('b', 64)], (new IdentifierChange)->prunable()->orderBy('id')->pluck('id')->all());

        Artisan::call('model:prune', ['--model' => [IdentifierChange::class]]);

        self::assertSame([str_repeat('c', 64)], DB::table('identifier_changes')->pluck('id')->all());
    }

    /**
     * Insert a pending change keyed by the repeated character, expiring at the
     * time.
     *
     * @param  string  $key
     * @param  string  $expiresAt
     * @return void
     */
    private static function insertChange(string $key, string $expiresAt): void
    {
        DB::table('identifier_changes')->insert([
            'id'           => str_repeat($key, 64),
            'guard'        => 'web',
            'type'         => 'email',
            'previous'     => 'ada@example.test',
            'identifier'   => 'ada@new.example.test',
            'request_id'   => '0195f4a2-7b1c-4000-8000-00000000000' . $key,
            'requested_at' => '2026-04-06 12:00:00',
            'expires_at'   => $expiresAt,
        ]);
    }
}
