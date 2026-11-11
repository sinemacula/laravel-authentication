<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\PrunesSessions;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Query-budget contracts for pruning sessions: one read and three deletes per
 * chunk, plus one final read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(PrunesSessions::class)]
final class SessionPruneQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * 2,500 revoked sessions are pruned in three chunks of at most 1,000 and a
     * final empty one, and the live session is kept.
     *
     * @return void
     */
    public function testPruningIsOneReadAndThreeDeletesPerChunkPlusOneRead(): void
    {
        foreach (array_chunk(range(1, 2500), 250) as $chunk) {
            DB::table('authentication_sessions')->insert(array_map(fn (int $index): array => $this->record($index, true), $chunk));
        }

        DB::table('authentication_sessions')->insert($this->record(0, false));

        $pruned = $this->assertQueryBudget(4, 9, static fn (): int => (new Session)->pruneAll());

        self::assertSame(2500, $pruned);
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * With nothing to prune, the run is the one read that finds nothing.
     *
     * @return void
     */
    public function testNothingToPruneCostsOneRead(): void
    {
        DB::table('authentication_sessions')->insert($this->record(0, false));

        self::assertSame(0, $this->assertQueryBudget(1, 0, static fn (): int => (new Session)->pruneAll()));
    }

    /**
     * One session row, revoked a year ago or live.
     *
     * @param  int  $index
     * @param  bool  $revoked
     * @return array<string, mixed>
     */
    private function record(int $index, bool $revoked): array
    {
        return [
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => (string) $index,
            'idle_expires_at'      => $this->now->copy()->addDays(30),
            'absolute_expires_at'  => $this->now->copy()->addDays(60),
            'revoked_at'           => $revoked ? $this->now->copy()->subYear() : null,
            'signed_in_at'         => $this->now->copy()->subYears(2),
        ];
    }
}
