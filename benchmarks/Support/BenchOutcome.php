<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Database\Capsule\Manager as Capsule;

/**
 * Proof, at set-up, that a benchmarked path reaches the outcome it is named
 * for, so a fixture that drifts (a device recording another guard, a token the
 * guard now rejects) fails the run instead of timing a rejection in the path's
 * place.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchOutcome
{
    /**
     * Throw unless the path reached its outcome.
     *
     * @param  string  $path
     * @param  bool  $reached
     * @return void
     *
     * @throws \LogicException
     */
    public static function assert(string $path, bool $reached): void
    {
        if (!$reached) {
            throw new \LogicException(sprintf('The %s benchmark does not reach the outcome it measures; fix its fixtures before timing it.', $path));
        }
    }

    /**
     * The fixture at the index of a pool whose fixtures are each used up once,
     * throwing once the pool is exhausted, so a run with more revolutions than
     * the pool holds fails instead of timing the refusal of a fixture already
     * used in place of the path.
     *
     * @template TFixture
     *
     * @param  string  $path
     * @param  list<TFixture>  $pool
     * @param  int  $index
     * @return TFixture
     *
     * @throws \LogicException
     */
    public static function take(string $path, array $pool, int $index): mixed
    {
        if (!array_key_exists($index, $pool)) {
            throw new \LogicException(sprintf('The %s benchmark has used up its %d fixtures; give it a larger pool or fewer revolutions.', $path, count($pool)));
        }

        return $pool[$index];
    }

    /**
     * Run the callback with the connection's query log on, and return the SQL
     * it ran.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<string>
     */
    public static function statementsOf(\Closure $callback): array
    {
        BenchDatabase::boot();

        $connection = Capsule::connection();

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        try {
            $callback();
        } finally {
            $connection->disableQueryLog();
        }

        $statements = array_map(static fn (array $query): string => strtolower($query['query']), $connection->getQueryLog());

        $connection->flushQueryLog();

        return $statements;
    }
}
