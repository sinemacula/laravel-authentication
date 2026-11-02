<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;

/**
 * An application's refresh token transport: its guard's `refresh_token` block
 * over the package defaults in `authentication.refresh_token`.
 *
 * A key the guard's block sets wins over the package's, inside `cookie` too.
 * Nothing falls back to a literal: a value missing at both levels where one is
 * required, a malformed value, or an unknown key fails closed with an
 * `InvalidArgumentException` naming the guard and the key.
 *
 * The `transport` is `body` (the body field, or the header when one is set) or
 * `cookie`. The cookie is always host-only. Its name, unless the application
 * sets one, is derived from the guard, so two applications on one host never
 * share a cookie: `__Host-<guard>_refresh_token` for a cookie application on
 * the path `/`, otherwise `__Secure-<guard>_refresh_token`. A body application
 * derives a name too, since it refuses its own cookie when a request brings
 * one; when its guard's name makes no cookie name and it sets none, it looks
 * for no cookie, since it never sets one. Two cookie applications whose names
 * are equal fail closed, naming both guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshTokenSettings
{
    /** @var list<string> Keys of a `refresh_token` block. */
    private const array KEYS = ['transport', 'body_field', 'header', 'cookie'];

    /** @var list<string> Keys of a `refresh_token` block's `cookie` block. */
    private const array COOKIE_KEYS = ['name', 'path', 'allowed_origins', 'csrf_header'];

    /** @var string A header or cookie name: an HTTP token without `.`, which PHP files as `_`, so the name would never be found. */
    private const string NAME_PATTERN = '/^[!#$%&\'*+^_`|~0-9A-Za-z-]+$/D';

    /** @var string A cookie path: starts with `/`, with no separator, space or control character. */
    private const string PATH_PATTERN = '/^\/[^;,\s\x00-\x1F\x7F]*$/D';

    /** @var string An origin: `http` or `https`, a lower-case host name or bracketed IPv6 address, and an optional port. */
    private const string ORIGIN_PATTERN = '/^https?:\/\/(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$/D';

    /** @var string The prefix of a cookie a browser keeps only with `Path=/` and no `Domain`. */
    private const string HOST_PREFIX = '__Host-';

    /** @var string The prefix of a cookie a browser keeps only when it was set over HTTPS with `Secure`. */
    private const string SECURE_PREFIX = '__Secure-';

    /** @var string What a derived cookie name ends with, after the guard's name. */
    private const string DERIVED_SUFFIX = '_refresh_token';

    /** @var list<string> Headers a cross-site form or simple request carries unset by the page: CORS-safelisted, browser-set, or cached credentials. */
    private const array BROWSER_HEADERS = [
        'accept', 'accept-charset', 'accept-encoding', 'accept-language', 'access-control-request-headers',
        'access-control-request-method', 'authorization', 'cache-control', 'connection', 'content-language',
        'content-length', 'content-type', 'cookie', 'cookie2', 'date', 'dnt', 'expect', 'host', 'keep-alive', 'origin',
        'pragma', 'priority', 'range', 'referer', 'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade',
        'upgrade-insecure-requests', 'user-agent', 'via',
    ];

    /** @var string The `Proxy-` and `Sec-` prefixes, whose headers only the browser sets. */
    private const string BROWSER_HEADER_PREFIX = '/^(?:proxy|sec)-/';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @param  string  $bodyField
     * @param  ?string  $header
     * @param  ?string  $cookieName
     * @param  ?string  $cookiePath
     * @param  list<string>  $allowedOrigins
     * @param  string  $csrfHeader
     */
    public function __construct(

        /** How the application's refresh token travels. */
        public Transport $transport,

        /** The body field that carries a body application's token. */
        public string $bodyField,

        /** The header that may carry a body application's token instead, or `null` for the body field only. */
        public ?string $header,

        /** The name of the application's refresh cookie, or `null` for a body application whose guard's name makes none. */
        public ?string $cookieName,

        /** The path the cookie is scoped to, or `null` for a body application, which sets none. */
        public ?string $cookiePath,

        /** Origins, besides the request's own, a cookie refresh may come from. */
        public array $allowedOrigins,

        /** The header a cookie refresh must carry, which a cross-site form cannot send. */
        public string $csrfHeader,
    ) {}

    /**
     * Read the guard's settings from the configuration, and refuse a cookie
     * application whose cookie name another cookie application uses.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forGuard(string $guard, ConfigRepository $config): self
    {
        $settings = self::merged($guard, $config);

        /** @var array<array-key, mixed> $cookie */
        $cookie = $settings['cookie'] ?? [];

        $transport = self::transport($guard, $settings['transport'] ?? null);
        $path      = self::path($guard, $cookie['path'] ?? null, $transport === Transport::COOKIE);
        $name      = self::cookieName($guard, $cookie['name'] ?? null, $transport, $path, $config);

        return new self(
            $transport,
            self::bodyField($guard, $settings['body_field'] ?? null),
            self::header($guard, $settings['header'] ?? null),
            $name,
            $path,
            self::origins($guard, $cookie['allowed_origins'] ?? null),
            self::csrfHeader($guard, $cookie['csrf_header'] ?? null),
        );
    }

    /**
     * The transport: `body` or `cookie`.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authentication\Http\Enums\Transport
     *
     * @throws \InvalidArgumentException
     */
    private static function transport(string $guard, mixed $value): Transport
    {
        return (is_string($value) ? Transport::tryFrom($value) : null)
            ?? throw new \InvalidArgumentException(self::message($guard, 'transport', 'must be `body` or `cookie`'));
    }

    /**
     * The cookie's name: the one the application sets, or the one derived from
     * its guard, `__Host-` only for a cookie application on the path `/`. A
     * cookie application needs a name: one whose guard's name makes none must
     * set one, a `__Host-` name it sets needs that path too, or the browser
     * would not keep the cookie, and no other cookie application may use it. A
     * body application never sets the cookie, so when its guard's name makes
     * none and it sets none, it looks for no cookie (`null`).
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @param  ?string  $path
     * @param  \Illuminate\Config\Repository  $config
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function cookieName(string $guard, mixed $value, Transport $transport, ?string $path, ConfigRepository $config): ?string
    {
        if ($transport === Transport::BODY) {
            return $value === null ? self::derivedName($guard, null) : self::name($guard, 'cookie.name', $value);
        }

        $name = $value === null ? self::derivedName($guard, $path) : self::name($guard, 'cookie.name', $value);

        if ($name === null) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.name', 'must be set: the guard\'s name does not make a cookie name'));
        }

        if (str_starts_with($name, self::HOST_PREFIX) && $path !== '/') {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.name', 'may start with `__Host-` only with `cookie.path` set to `/`'));
        }

        self::assertUniqueCookie($guard, $name, $config);

        return $name;
    }

    /**
     * The cookie name derived from the guard for a cookie on the path, or
     * `null` when the guard's name does not make a cookie name.
     *
     * @param  string  $guard
     * @param  ?string  $path
     * @return ?string
     */
    private static function derivedName(string $guard, ?string $path): ?string
    {
        $derived = ($path === '/' ? self::HOST_PREFIX : self::SECURE_PREFIX) . $guard . self::DERIVED_SUFFIX;

        return preg_match(self::NAME_PATTERN, $derived) === 1 ? $derived : null;
    }

    /**
     * Refuse a cookie name another `jwt` guard that also travels by cookie
     * uses, naming both guards: two applications on one host would overwrite
     * each other's cookie. Only the other guards' `transport`, `cookie.name`
     * and `cookie.path` are read; a value of theirs that is malformed fails
     * when their own transport is read.
     *
     * @param  string  $guard
     * @param  string  $name
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertUniqueCookie(string $guard, string $name, ConfigRepository $config): void
    {
        foreach (JwtGuards::names($config) as $other) {

            if ($other !== $guard && self::cookieOf($other, $config) === $name) {
                $message = "Refresh token transport for guard [{$guard}]: its refresh cookie `{$name}` is also guard [{$other}]'s;"
                    . ' give one of them another `refresh_token.cookie.name`.';

                throw new \InvalidArgumentException($message);
            }
        }
    }

    /**
     * The cookie name a guard that travels by cookie uses, read leniently from
     * its `transport`, `cookie.name` and `cookie.path`, or `null` for a guard
     * that does not.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return ?string
     */
    private static function cookieOf(string $guard, ConfigRepository $config): ?string
    {
        $read = static fn (string $key): mixed => $config->get("auth.guards.{$guard}.refresh_token.{$key}", $config->get("authentication.refresh_token.{$key}"));

        if ($read('transport') !== Transport::COOKIE->value) {
            return null;
        }

        $name = $read('cookie.name');
        $path = $read('cookie.path');

        if (is_string($name)) {
            return $name;
        }

        return self::derivedName($guard, is_string($path) ? $path : null);
    }

    /**
     * The package block with the guard's over it, its `cookie` the two `cookie`
     * blocks merged the same way.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function merged(string $guard, ConfigRepository $config): array
    {
        $guardConfig = $config->get("auth.guards.{$guard}");

        if (!is_array($guardConfig)) {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not configured.");
        }

        $package   = self::block($guard, $config->get('authentication.refresh_token'), '`authentication.refresh_token`', self::KEYS);
        $overrides = self::block($guard, $guardConfig['refresh_token'] ?? [], 'the guard\'s `refresh_token`', self::KEYS);

        $cookie = array_replace(
            self::block($guard, $package['cookie'] ?? [], '`authentication.refresh_token.cookie`', self::COOKIE_KEYS),
            self::block($guard, $overrides['cookie'] ?? [], 'the guard\'s `refresh_token.cookie`', self::COOKIE_KEYS),
        );

        return array_replace($package, $overrides, ['cookie' => $cookie]);
    }

    /**
     * A configuration block holding only known keys.
     *
     * @param  string  $guard
     * @param  mixed  $block
     * @param  string  $name
     * @param  list<string>  $known
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function block(string $guard, mixed $block, string $name, array $known): array
    {
        if (!is_array($block)) {
            throw new \InvalidArgumentException("Refresh token transport for guard [{$guard}]: {$name} must be an array.");
        }

        foreach (array_keys($block) as $key) {
            if (!in_array($key, $known, true)) {
                throw new \InvalidArgumentException("Refresh token transport for guard [{$guard}]: {$name} has an unknown key `{$key}`.");
            }
        }

        return $block;
    }

    /**
     * The body field: a name PHP keeps as it is in a form body.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function bodyField(string $guard, mixed $value): string
    {
        if (!RequestBody::isFieldName($value)) {
            throw new \InvalidArgumentException(self::message($guard, 'body_field', 'must be a field name without `.`, spaces or brackets'));
        }

        return $value;
    }

    /**
     * The CSRF header: a header name, and, in any letter case, none that a
     * cross-site form or simple request can carry without the page setting it.
     * A `_` is read as `-`, as Symfony's header bag reads it, so `Content_Type`
     * is refused as `Content-Type` is.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function csrfHeader(string $guard, mixed $value): string
    {
        $header = self::name($guard, 'cookie.csrf_header', $value);

        $read = strtolower(strtr($header, '_', '-'));

        if (in_array($read, self::BROWSER_HEADERS, true) || preg_match(self::BROWSER_HEADER_PREFIX, $read) === 1) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.csrf_header', 'must be a custom header, not one a browser sends on its own'));
        }

        return $header;
    }

    /**
     * A header or cookie name PHP keeps as it is.
     *
     * @param  string  $guard
     * @param  string  $key
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function name(string $guard, string $key, mixed $value): string
    {
        if (!is_string($value) || preg_match(self::NAME_PATTERN, $value) !== 1) {
            throw new \InvalidArgumentException(self::message($guard, $key, 'must be a header or cookie name without `.`'));
        }

        return $value;
    }

    /**
     * The header that may carry a body application's token: `null` for the body
     * field only, or a header name PHP keeps as it is.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function header(string $guard, mixed $value): ?string
    {
        return $value === null ? null : self::name($guard, 'header', $value);
    }

    /**
     * The cookie path: required for a cookie application, and a path when set.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @param  bool  $required
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function path(string $guard, mixed $value, bool $required): ?string
    {
        if ($value === null && !$required) {
            return null;
        }

        if (!is_string($value) || preg_match(self::PATH_PATTERN, $value) !== 1) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.path', 'must be the path of the refresh route, starting with `/`, for a cookie application'));
        }

        return $value;
    }

    /**
     * The allowed origins: a list of exact `scheme://host[:port]` origins, in
     * lower case, as a browser sends them.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function origins(string $guard, mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value) || array_filter($value, static fn (mixed $origin): bool => self::isOrigin($origin)) !== $value) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.allowed_origins', 'must be a list of origins, each `scheme://host[:port]` in lower case'));
        }

        /** @var list<string> $value */
        return $value;
    }

    /**
     * Whether the value is an exact `http` or `https` origin in lower case,
     * with no path, query, fragment or credentials.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isOrigin(mixed $value): bool
    {
        return is_string($value) && preg_match(self::ORIGIN_PATTERN, $value) === 1;
    }

    /**
     * The message naming the guard and the key a value is wrong for.
     *
     * @param  string  $guard
     * @param  string  $key
     * @param  string  $requirement
     * @return string
     */
    private static function message(string $guard, string $key, string $requirement): string
    {
        return "Refresh token transport for guard [{$guard}]: `refresh_token.{$key}` {$requirement}.";
    }
}
