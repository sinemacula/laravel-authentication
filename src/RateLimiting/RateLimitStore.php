<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Models\RateLimit;

/**
 * The statements behind the attempt limiter, each change to a count a single
 * atomic statement on the write PDO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RateLimitStore
{
    /**
     * Take one slot of the counter's window, returning the window as stored, or
     * the Unix time a full window ends.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @param  int  $end
     * @return int|string
     */
    public function take(string $key, int $max, int $now, int $end): int|string
    {
        if ($this->writeCount($key, $now, $end, $max) || $this->storeNewCounter($key, $end) || $this->writeCount($key, $now, $end, $max)) {
            return $this->format($end);
        }

        return $this->takeFromStoredWindow($key, $max, $now);
    }

    /**
     * Count one attempt against the counter, however many it already has.
     *
     * @param  string  $key
     * @param  int  $now
     * @param  int  $end
     * @return void
     */
    public function record(string $key, int $now, int $end): void
    {
        if ($this->writeCount($key, $now, $end) || $this->storeNewCounter($key, $end)) {
            return;
        }

        $this->writeCount($key, $now, $end);
    }

    /**
     * Give back one slot taken from the window that ends at `$window`, as
     * `take()` returned it.
     *
     * @param  string  $key
     * @param  string  $window
     * @return void
     */
    public function giveBack(string $key, string $window): void
    {
        $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '>', 0)
            ->decrement('hits');
    }

    /**
     * Read the counters, by key, as the number of attempts in their window and
     * the Unix time it ends.
     *
     * @param  list<string>  $keys
     * @return array<string, array{hits: int, ends: int}>
     */
    public function read(array $keys): array
    {
        $counters = [];

        foreach (RateLimit::query()->useWritePdo()->whereIn('key', $keys)->get() as $counter) {
            $counters[$counter->key] = ['hits' => $counter->hits, 'ends' => $counter->window_ends_at->getTimestamp()];
        }

        return $counters;
    }

    /**
     * Take a slot from the counter's stored window when it is live and has
     * room, else return the Unix time the attempt may be made again.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @return int|string
     */
    private function takeFromStoredWindow(string $key, int $max, int $now): int|string
    {
        $counter = $this->read([$key])[$key] ?? null;

        if ($counter === null || $counter['ends'] <= $now) {
            return $now + 1;
        }

        $window = $this->format($counter['ends']);

        if ($counter['hits'] < $max && $this->countIn($key, $window, $max)) {
            return $window;
        }

        return $counter['ends'];
    }

    /**
     * Add one attempt to the counter's stored window while it is still stored
     * and has room.
     *
     * @param  string  $key
     * @param  string  $window
     * @param  int  $max
     * @return bool
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function countIn(string $key, string $window, int $max): bool
    {
        return $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '<', $max)
            ->increment('hits') === 1;
    }

    /**
     * Add one attempt to an existing counter, restarting its window when it has
     * ended, and returning whether the counter was changed.
     *
     * The count is assigned first since MySQL applies UPDATE assignments left
     * to right.
     *
     * @param  string  $key
     * @param  int  $now
     * @param  int  $end
     * @param  ?int  $max
     * @return bool
     *
     * @phpstan-impure
     */
    private function writeCount(string $key, int $now, int $end, ?int $max = null): bool
    {
        $connection = $this->connection();
        $grammar    = $connection->getQueryGrammar();
        $table      = $grammar->wrapTable($this->model()->getTable());
        $hits       = $grammar->wrap('hits');
        $window     = $grammar->wrap('window_ends_at');
        $nowAt      = $this->format($now);

        $sql = "update {$table} set {$hits} = case when {$window} <= ? then 1 else {$hits} + 1 end,"
            . " {$window} = case when {$window} <= ? then ? else {$window} end where {$grammar->wrap('key')} = ?";

        $bindings = [$nowAt, $nowAt, $this->format($end), $key];

        if ($max !== null) {
            $sql .= " and ({$window} <= ? or ({$window} = ? and {$hits} < ?))";

            array_push($bindings, $nowAt, $this->format($end), $max);
        }

        return $connection->update($sql, $bindings) === 1;
    }

    /**
     * Create the counter with this attempt, returning whether this call created
     * it.
     *
     * @param  string  $key
     * @param  int  $end
     * @return bool
     *
     * @phpstan-impure
     */
    private function storeNewCounter(string $key, int $end): bool
    {
        return $this->table()->insertOrIgnore([
            'key'            => $key,
            'hits'           => 1,
            'window_ends_at' => $this->format($end),
        ]) === 1;
    }

    /**
     * A query on the counters' table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(): Builder
    {
        return $this->connection()->table($this->model()->getTable());
    }

    /**
     * The counters' connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return $this->model()->getConnection();
    }

    /**
     * A counter model, which carries the configured table and connection.
     *
     * @return \SineMacula\Laravel\Authentication\Models\RateLimit
     */
    private function model(): RateLimit
    {
        return new RateLimit;
    }

    /**
     * Format a Unix time as the counters' connection stores times.
     *
     * @param  int  $timestamp
     * @return string
     */
    private function format(int $timestamp): string
    {
        $formatted = $this->model()->fromDateTime(CarbonImmutable::createFromTimestamp($timestamp, date_default_timezone_get()));

        return (string) $formatted;
    }
}
