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
 * column's 512 characters. PostgreSQL, and MySQL in strict mode, reject invalid
 * UTF-8 and an over-long value, and a crafted header must not turn a request
 * into a server error; PostgreSQL cannot store a NUL byte in text, and through
 * PDO a value is cut short at the first one. A value that is missing, invalid,
 * or empty after cleaning is `null`.
 *
 * The package records last use with it; code that creates a device should
 * record `created_ip` and `created_user_agent` through it too, from
 * `fromRequest()` or the constructor.
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

    /** @var ?string Validated IP address the client came from. */
    public ?string $ip;

    /** @var ?string Cleaned user agent the client sent. */
    public ?string $userAgent;

    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     */
    public function __construct(?string $ip, ?string $userAgent)
    {
        $this->ip        = self::cleanIp($ip);
        $this->userAgent = ClientText::clean($userAgent, self::USER_AGENT_MAX_LENGTH);
    }

    /**
     * Read the client context of a request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent());
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
}
