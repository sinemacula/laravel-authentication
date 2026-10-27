<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/**
 * Finds the attempt limiter's counters the way its keys are documented: an
 * HMAC-SHA256 digest of the parts joined by NUL bytes, under a key derived from
 * the application key, so tests compute a counter's key themselves rather than
 * asking the limiter for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithRateLimits
{
    /**
     * The key of the counter for the parts: the guard, flow, scope and value,
     * or, for an account, the flow, `per_account` and the account.
     *
     * @param  string  ...$parts
     * @return string
     */
    protected static function counterKey(string ...$parts): string
    {
        $secret = hash_hmac('sha256', 'sinemacula/laravel-authentication rate limit counters', Config::string('app.key'), true);

        return hash_hmac('sha256', implode("\0", $parts), $secret);
    }

    /**
     * The hits on the counter for the parts, 0 when it has none.
     *
     * @param  string  ...$parts
     * @return int
     */
    protected static function counterHits(string ...$parts): int
    {
        $hits = DB::table('rate_limits')->where('key', self::counterKey(...$parts))->value('hits');

        return is_numeric($hits) ? (int) $hits : 0;
    }
}
