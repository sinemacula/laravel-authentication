<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;

/**
 * Request fixtures for the benchmark harnesses, and the refresh token transport
 * their guards read requests with.
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

    /**
     * The package's default refresh token transport: the body field or the
     * header, for an application named `api`.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    public static function refreshTransport(): RefreshTokenTransport
    {
        return new RefreshTokenTransport(new RefreshTokenSettings(
            Transport::BODY,
            'refresh_token',
            'X-Refresh-Token',
            '__Secure-api_refresh_token',
            null,
            [],
            'X-Requested-With',
        ));
    }
}
