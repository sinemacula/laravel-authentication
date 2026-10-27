<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\PrunesDevices;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Query-budget contracts for pruning devices: each chunk is one conditional
 * `DELETE`, nothing is read, and the run ends with the one `DELETE` that finds
 * nothing left, so N prunable devices cost ceil(N / chunk) + 1 statements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(PrunesDevices::class)]
final class DevicePruneQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * 2,500 revoked devices are pruned in three chunks of at most 1,000 and a
     * final empty one, and the live device is kept.
     *
     * @return void
     */
    public function testPruningIsOneDeletePerChunkPlusOne(): void
    {
        foreach (array_chunk(range(1, 2500), 250) as $chunk) {
            DB::table('devices')->insert(array_map(fn (int $index): array => $this->device($index, true), $chunk));
        }

        DB::table('devices')->insert($this->device(0, false));

        $pruned = $this->assertQueryBudget(0, 4, static fn (): int => (new Device)->pruneAll());

        self::assertSame(2500, $pruned);
        self::assertSame(1, DB::table('devices')->count());
    }

    /**
     * With nothing to prune, the run is the one `DELETE` that finds nothing.
     *
     * @return void
     */
    public function testNothingToPruneCostsOneDelete(): void
    {
        DB::table('devices')->insert($this->device(0, false));

        self::assertSame(0, $this->assertQueryBudget(0, 1, static fn (): int => (new Device)->pruneAll()));
    }

    /**
     * One device row, revoked a year ago or live.
     *
     * @param  int  $index
     * @param  bool  $revoked
     * @return array<string, mixed>
     */
    private function device(int $index, bool $revoked): array
    {
        return [
            'id'                   => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => (string) $index,
            'idle_expires_at'      => $this->now->copy()->addDays(30),
            'absolute_expires_at'  => $this->now->copy()->addDays(60),
            'revoked_at'           => $revoked ? $this->now->copy()->subYear() : null,
            'signed_in_at'         => $this->now->copy()->subYears(2),
        ];
    }
}
