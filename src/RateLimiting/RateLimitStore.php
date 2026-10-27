<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Models\RateLimit;

/**
 * The statements behind the attempt limiter, on the counters' own connection
 * and always on its write PDO. Every change to a count is one statement that
 * the database applies atomically, so concurrent attempts on any number of
 * servers can never read a count, add to it, and write it back over each other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RateLimitStore
{
    /**
     * Take one slot of the counter's window, unless the window is full: a
     * counter whose window has ended starts the window that ends at `$end` with
     * this attempt, and a missing counter is created with it. Returns the end
     * of the window the slot was taken from, as stored; when the window is
     * full, the Unix time it ends instead.
     *
     * A live counter whose window does not end at `$end` was started under a
     * different `decay_seconds`, or by a server whose clock is ahead: its own
     * window is kept and counted in, so a change of configuration neither
     * forgives earlier attempts nor loses track of the window a slot came from.
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
     * `take()` returned it; a counter that has moved on to a later window, or
     * holds no attempt, is left alone.
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
     * Read the counter the statements could not take a slot from, and take one
     * from its stored window when that is live, does not end at the computed
     * end, and has room. Returns that window as stored, or the Unix time the
     * attempt may be made again: the stored window's end, and never earlier
     * than a second from now (a counter that ended or went in the meantime is
     * worth one more try).
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
     * Add one attempt to the counter's stored window, in one statement, while
     * that window is still the one stored and has room. Returns whether it did.
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
     * Add one attempt to an existing counter in one statement: the counter's
     * window restarts when it has ended, and, given a maximum, only a window
     * that ends at `$end` and has room is counted in (any other live window is
     * left untouched). Returns whether the counter was changed.
     *
     * The count is assigned before the window: MySQL evaluates the assignments
     * of an UPDATE from left to right, so the count's condition must read the
     * window before it is moved.
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
     * Create the counter with this attempt, unless another request created it
     * first. Returns whether this call created it.
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
     * A query on the counters' table, for the writes the query builder can
     * express.
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
     * Format a Unix time as the counters' connection stores times, in the
     * application timezone.
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
