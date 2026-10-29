<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Http\Request;

/**
 * Request fixtures for the benchmark harnesses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchRequest
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A request from a typical client, whose IP address and user agent the
     * last-use listener records.
     *
     * @return \Illuminate\Http\Request
     */
    public static function client(): Request
    {
        return Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR'     => '203.0.113.7',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15',
        ]);
    }
}
