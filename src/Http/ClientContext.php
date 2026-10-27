<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;

/**
 * The client a request came from, as the package stores it on a device: its IP
 * address and its user agent.
 *
 * Both come from the client and are made safe to store rather than trusted: an
 * IP address is kept only when it is a valid IPv4 or IPv6 address, and a user
 * agent has NUL bytes removed, invalid UTF-8 replaced, and is cut to the
 * column's 512 characters, because PostgreSQL rejects NUL and invalid UTF-8 in
 * a text column and a crafted header must not turn a request into a server
 * error. A value that is missing, invalid, or empty after cleaning is `null`.
 *
 * The package records last use with it. Code that creates a device records the
 * client it was created from (`created_ip`, `created_user_agent`) with
 * `fromRequest()` too, so those columns are cleaned the same way.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /** @var int Longest user agent kept, in characters. */
    private const int USER_AGENT_MAX_LENGTH = 512;

    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     */
    public function __construct(

        /** Validated IP address the request came from. */
        public ?string $ip,

        /** Cleaned user agent the request sent. */
        public ?string $userAgent,
    ) {}

    /**
     * Read the client context of a request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self(self::cleanIp($request->ip()), self::cleanUserAgent($request->userAgent()));
    }

    /**
     * Keep an IP address only when it is a valid IPv4 or IPv6 address.
     *
     * @param  ?string  $ip
     * @return ?string
     */
    private static function cleanIp(?string $ip): ?string
    {
        return $ip !== null && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    /**
     * Make a user agent safe to store in a UTF-8 text column of the maximum
     * length.
     *
     * @param  ?string  $userAgent
     * @return ?string
     */
    private static function cleanUserAgent(?string $userAgent): ?string
    {
        if ($userAgent === null) {
            return null;
        }

        $cleaned = mb_substr(mb_scrub(str_replace("\0", '', $userAgent), 'UTF-8'), 0, self::USER_AGENT_MAX_LENGTH, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
