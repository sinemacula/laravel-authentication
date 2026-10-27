<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Carbon\Carbon;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\PrunesDevices;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\ScopedRenamedPruningDevice;
use Tests\TestCase;

/**
 * Integration tests for pruning devices with Laravel's `model:prune`, against
 * the shipped table on each supported database: which ended sessions are
 * deleted at each boundary of the retention, and how a custom model opts in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(PrunesDevices::class)]
final class DevicePruningIntegrationTest extends TestCase
{
    /** @var string The frozen time every test prunes at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var string The cutoff for the default 30 days of retention. */
    private const string CUTOFF = '2026-12-16 10:00:00';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse(self::NOW));
    }

    /**
     * Release the clock and drop the custom model's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Schema::dropIfExists('scoped_renamed_pruning_devices');

        parent::tearDown();
    }

    /**
     * A device revoked, or past either deadline, at or before the cutoff is
     * pruned; one that ended a second after it is kept, as is a live session
     * however long ago it was created.
     *
     * @return void
     */
    public function testPrunesDevicesWhoseSessionEndedAtOrBeforeTheCutoff(): void
    {
        $cutoff = Carbon::parse(self::CUTOFF);
        $future = Carbon::parse(self::NOW)->addDays(30);

        $this->insertDevice('revoked-before', revokedAt: $cutoff->copy()->subSecond());
        $this->insertDevice('revoked-at', revokedAt: $cutoff);
        $this->insertDevice('revoked-after', revokedAt: $cutoff->copy()->addSecond());
        $this->insertDevice('idle-before', idle: $cutoff->copy()->subSecond());
        $this->insertDevice('idle-at', idle: $cutoff);
        $this->insertDevice('idle-after', idle: $cutoff->copy()->addSecond());
        $this->insertDevice('absolute-before', idle: $future, absolute: $cutoff->copy()->subSecond());
        $this->insertDevice('absolute-at', idle: $future, absolute: $cutoff);
        $this->insertDevice('absolute-after', idle: $future, absolute: $cutoff->copy()->addSecond());
        $this->insertDevice('live', createdAt: Carbon::parse('2020-01-01 00:00:00'));

        Artisan::call('model:prune', ['--model' => [Device::class]]);

        self::assertEqualsCanonicalizing(
            ['client-revoked-after', 'client-idle-after', 'client-absolute-after', 'client-live'],
            DB::table('devices')->pluck('client_name')->all(),
        );
    }

    /**
     * The retention is read when pruning runs: with 0 days a device is pruned
     * from the second its session ended, and a digit string, as `env()` returns
     * one, counts as its number of days.
     *
     * @return void
     */
    public function testRetentionIsReadWhenPruningRuns(): void
    {
        $now = Carbon::parse(self::NOW);

        $this->insertDevice('ended-now', idle: $now);
        $this->insertDevice('ends-next-second', idle: $now->copy()->addSecond());
        $this->insertDevice('revoked-a-week-ago', revokedAt: $now->copy()->subDays(7));
        $this->insertDevice('revoked-six-days-ago', revokedAt: $now->copy()->subDays(6));

        config()->set('authentication.device.prune_after_days', '7');

        Artisan::call('model:prune', ['--model' => [Device::class]]);

        self::assertEqualsCanonicalizing(
            ['client-ended-now', 'client-ends-next-second', 'client-revoked-six-days-ago'],
            DB::table('devices')->pluck('client_name')->all(),
        );

        config()->set('authentication.device.prune_after_days', 0);

        Artisan::call('model:prune', ['--model' => [Device::class]]);

        self::assertEqualsCanonicalizing(['client-ends-next-second'], DB::table('devices')->pluck('client_name')->all());
    }

    /**
     * `--pretend` counts the devices that would be pruned and deletes nothing.
     *
     * @return void
     */
    public function testPretendCountsWithoutDeleting(): void
    {
        $this->insertDevice('revoked', revokedAt: Carbon::parse(self::CUTOFF));
        $this->insertDevice('live');

        Artisan::call('model:prune', ['--model' => [Device::class], '--pretend' => true]);

        self::assertStringContainsString('1 [' . Device::class . '] records will be pruned.', Artisan::output());
        self::assertSame(2, DB::table('devices')->count());
    }

    /**
     * More devices than one chunk are all pruned, in chunks, and the live ones
     * are kept.
     *
     * @return void
     */
    public function testPrunesInChunks(): void
    {
        $rows = [];

        for ($index = 0; $index < 25; $index++) {
            $rows[] = $this->deviceRow('revoked-' . $index, revokedAt: Carbon::parse(self::CUTOFF));
        }

        DB::table('devices')->insert($rows);

        $this->insertDevice('live');

        Artisan::call('model:prune', ['--model' => [Device::class], '--chunk' => 10]);

        self::assertSame(['client-live'], DB::table('devices')->pluck('client_name')->all());
    }

    /**
     * A custom model opts in with the trait alone: pruning reads its renamed
     * columns, and its own global scope still limits what is pruned, so an
     * ended device the scope excludes is kept.
     *
     * @return void
     */
    public function testACustomModelPrunesThroughItsOwnColumnsAndScope(): void
    {
        Schema::create('scoped_renamed_pruning_devices', static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('guard');
            $table->dateTime('ended_at', 0)->nullable();
            $table->dateTime('idle_until', 0);
            $table->dateTime('valid_until', 0);
        });

        $cutoff = Carbon::parse(self::CUTOFF);
        $future = Carbon::parse(self::NOW)->addDays(30);

        DB::table('scoped_renamed_pruning_devices')->insert([
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => $cutoff, 'idle_until' => $future, 'valid_until' => $future],
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $cutoff, 'valid_until' => $future],
            ['id' => (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $future, 'valid_until' => $cutoff],
            ['id' => $live = (string) Str::uuid7(), 'guard' => 'api', 'ended_at' => null, 'idle_until' => $future, 'valid_until' => $future],
            ['id' => $other = (string) Str::uuid7(), 'guard' => 'web', 'ended_at' => null, 'idle_until' => $cutoff, 'valid_until' => $future],
        ]);

        Artisan::call('model:prune', ['--model' => [ScopedRenamedPruningDevice::class]]);

        self::assertEqualsCanonicalizing([$live, $other], DB::table('scoped_renamed_pruning_devices')->pluck('id')->all());
    }

    /**
     * Insert one device of the shipped table.
     *
     * @param  string  $name
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @param  ?\Carbon\Carbon  $absolute
     * @param  ?\Carbon\Carbon  $createdAt
     * @return void
     */
    private function insertDevice(string $name, ?Carbon $revokedAt = null, ?Carbon $idle = null, ?Carbon $absolute = null, ?Carbon $createdAt = null): void
    {
        DB::table('devices')->insert($this->deviceRow($name, $revokedAt, $idle, $absolute, $createdAt));
    }

    /**
     * One row of the shipped table: a session of the `api` guard whose
     * deadlines are a month ahead unless given.
     *
     * @param  string  $name
     * @param  ?\Carbon\Carbon  $revokedAt
     * @param  ?\Carbon\Carbon  $idle
     * @param  ?\Carbon\Carbon  $absolute
     * @param  ?\Carbon\Carbon  $createdAt
     * @return array<string, mixed>
     */
    private function deviceRow(string $name, ?Carbon $revokedAt = null, ?Carbon $idle = null, ?Carbon $absolute = null, ?Carbon $createdAt = null): array
    {
        $future = Carbon::parse(self::NOW)->addDays(30);

        return [
            'id'                   => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'client_name'          => 'client-' . $name,
            'idle_expires_at'      => $idle     ?? $future,
            'absolute_expires_at'  => $absolute ?? $future->copy()->addDays(30),
            'revoked_at'           => $revokedAt,
            'revoked_reason'       => $revokedAt === null ? null : 'revoked',
            'signed_in_at'         => $createdAt ?? Carbon::parse(self::NOW),
            'created_at'           => $createdAt ?? Carbon::parse(self::NOW),
            'updated_at'           => $createdAt ?? Carbon::parse(self::NOW),
        ];
    }
}
