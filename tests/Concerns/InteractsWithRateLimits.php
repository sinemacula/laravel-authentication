<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/**
 * Finds the attempt limiter's counters by computing their documented keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithRateLimits
{
    /**
     * The key of the counter for the parts.
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
