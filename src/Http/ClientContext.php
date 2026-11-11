<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Exception\RequestExceptionInterface;

/**
 * The client a request came from, and the facts a cookie application's
 * same-site check judges it by.
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

    /** @var string An origin, or a scheme and host, kept: 1 to 512 printable ASCII characters. */
    private const string ORIGIN_PATTERN = '/^[\x21-\x7E]{1,512}$/D';

    /** @var string A header name kept: an HTTP token, as the header bag files it. */
    private const string TOKEN_PATTERN = '/^[!#$%&\'*+.^`|~0-9a-z-]+$/D';

    /** @var ?string Validated IP address the client came from. */
    public ?string $ip;

    /** @var ?string Cleaned user agent the client sent. */
    public ?string $userAgent;

    /** @var ?string The `Origin` the request presented, as it presented it. */
    public ?string $origin;

    /** @var ?string The request's own scheme and host (with a port that is not the scheme's own). */
    public ?string $schemeAndHost;

    /** @var list<string> The names of the headers the request carried whose first value is a non-empty string. */
    public array $nonEmptyHeaders;

    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?string  $origin
     * @param  ?string  $schemeAndHost
     * @param  array<array-key, string>  $nonEmptyHeaders
     */
    public function __construct(?string $ip, ?string $userAgent, ?string $origin = null, ?string $schemeAndHost = null, array $nonEmptyHeaders = [])
    {
        $this->ip              = self::cleanIp($ip);
        $this->userAgent       = ClientText::clean($userAgent, self::USER_AGENT_MAX_LENGTH);
        $this->origin          = self::cleanOrigin($origin);
        $this->schemeAndHost   = self::cleanOrigin($schemeAndHost);
        $this->nonEmptyHeaders = self::headerNames($nonEmptyHeaders);
    }

    /**
     * Read the client context of a request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent(), $request->headers->get('Origin'), self::schemeAndHostOf($request), self::nonEmptyHeadersOf($request));
    }

    /**
     * Read a request's same-site facts alone, with no IP address or user agent.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     *
     * @internal
     */
    public static function sameSiteFactsOf(Request $request): self
    {
        return new self(null, null, $request->headers->get('Origin'), self::schemeAndHostOf($request), self::nonEmptyHeadersOf($request));
    }

    /**
     * Whether the request carried the named header with a non-empty first
     * value.
     *
     * @param  string  $name
     * @return bool
     */
    public function carriesHeader(string $name): bool
    {
        return in_array(self::headerName($name), $this->nonEmptyHeaders, true);
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
     * Keep an origin only when it is 1 to 512 printable ASCII characters.
     *
     * @param  ?string  $origin
     * @return ?string
     */
    private static function cleanOrigin(?string $origin): ?string
    {
        return $origin !== null && preg_match(self::ORIGIN_PATTERN, $origin) === 1 ? $origin : null;
    }

    /**
     * The header name as Symfony's header bag files it: lower case, with `_`
     * read as `-`.
     *
     * @param  string  $name
     * @return string
     */
    private static function headerName(string $name): string
    {
        return strtr($name, '_ABCDEFGHIJKLMNOPQRSTUVWXYZ', '-abcdefghijklmnopqrstuvwxyz');
    }

    /**
     * The header names as the header bag files them, once each, dropping any
     * that is not an HTTP token.
     *
     * @param  array<array-key, string>  $names
     * @return list<string>
     */
    private static function headerNames(array $names): array
    {
        $filed = array_map(self::headerName(...), $names);

        return array_values(array_unique(array_filter($filed, static fn (string $name): bool => preg_match(self::TOKEN_PATTERN, $name) === 1)));
    }

    /**
     * The request's scheme and host, or `null` when it has no host or Symfony
     * refuses its host or its forwarded headers.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?string
     */
    private static function schemeAndHostOf(Request $request): ?string
    {
        $copy = clone $request;

        try {
            return $copy->getHost() === '' ? null : $copy->getSchemeAndHttpHost();
        } catch (RequestExceptionInterface) { // @phpstan-ignore catch.neverThrown (Symfony throws it without declaring it)
            return null;
        }
    }

    /**
     * The names of the headers the request carried whose first value is a
     * non-empty string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return list<string>
     */
    private static function nonEmptyHeadersOf(Request $request): array
    {
        $names = [];

        foreach ($request->headers->all() as $name => $values) {

            $first = $values[0] ?? null;

            if ($first === null || $first === '') {
                continue;
            }

            $names[] = $name;
        }

        return $names;
    }
}
