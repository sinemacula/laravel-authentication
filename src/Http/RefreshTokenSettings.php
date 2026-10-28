<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

/**
 * A guard's refresh token transport: its `refresh_token` block over the package
 * defaults in `authentication.refresh_token`.
 *
 * A key the guard's block sets wins over the package's, inside `cookie` too.
 * Nothing falls back to a literal: a value missing at both levels where one is
 * required, a malformed value, or an unknown key fails closed with an
 * `InvalidArgumentException` naming the guard and the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshTokenSettings
{
    /** @var list<string> Keys of a `refresh_token` block. */
    private const array KEYS = ['sources', 'body_field', 'header', 'cookie'];

    /** @var list<string> Keys of a `refresh_token` block's `cookie` block. */
    private const array COOKIE_KEYS = ['name', 'path', 'domain', 'allowed_origins', 'csrf_header'];

    /** @var string A header or cookie name: an HTTP token without `.`, which PHP files as `_`, so the name would never be found. */
    private const string NAME_PATTERN = '/^[!#$%&\'*+^_`|~0-9A-Za-z-]+$/D';

    /** @var string A body field: no `.` or space, which PHP files as `_` in a form body, and no bracket, which nests it. */
    private const string FIELD_PATTERN = '/^[^\s.\[\]\x00-\x1F\x7F]+$/D';

    /** @var string A cookie path: starts with `/`, with no separator, space or control character. */
    private const string PATH_PATTERN = '/^\/[^;,\s\x00-\x1F\x7F]*$/D';

    /** @var string A cookie domain: a host name, optionally with a leading dot. */
    private const string DOMAIN_PATTERN = '/^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/D';

    /** @var string An origin: `http` or `https`, a lower-case host name or bracketed IPv6 address, and an optional port. */
    private const string ORIGIN_PATTERN = '/^https?:\/\/(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$/D';

    /** @var string The prefix of a cookie a browser keeps only with `Path=/` and no `Domain`. */
    private const string HOST_PREFIX = '__Host-';

    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>  $sources
     * @param  string  $bodyField
     * @param  string  $header
     * @param  string  $cookieName
     * @param  ?string  $cookiePath
     * @param  ?string  $cookieDomain
     * @param  list<string>  $allowedOrigins
     * @param  string  $csrfHeader
     */
    public function __construct(

        /** The sources a refresh token is read from. */
        public array $sources,

        /** The body field that carries the token. */
        public string $bodyField,

        /** The header that carries the token. */
        public string $header,

        /** The name of the refresh cookie. */
        public string $cookieName,

        /** The path the cookie is scoped to, or `null` when the cookie is not a source. */
        public ?string $cookiePath,

        /** The domain the cookie is scoped to, or `null` for the request's host only. */
        public ?string $cookieDomain,

        /** Origins, besides the request's own, a cookie refresh may come from. */
        public array $allowedOrigins,

        /** The header a cookie refresh must carry, which a cross-site form cannot send. */
        public string $csrfHeader,
    ) {}

    /**
     * Read the guard's settings from the configuration.
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

        $sources     = self::sources($guard, $settings['sources'] ?? null);
        $readsCookie = in_array(RefreshTokenSource::COOKIE, $sources, true);
        $name        = self::name($guard, 'cookie.name', $cookie['name'] ?? null);
        $path        = self::path($guard, $cookie['path'] ?? null, $readsCookie);
        $domain      = self::domain($guard, $cookie['domain'] ?? null);

        self::assertHostCookie($guard, $readsCookie, $name, $path, $domain);

        return new self(
            $sources,
            self::bodyField($guard, $settings['body_field'] ?? null),
            self::name($guard, 'header', $settings['header'] ?? null),
            $name,
            $path,
            $domain,
            self::origins($guard, $cookie['allowed_origins'] ?? null),
            self::name($guard, 'cookie.csrf_header', $cookie['csrf_header'] ?? null),
        );
    }

    /**
     * Reject a `__Host-` cookie a browser would not keep: one with a path other
     * than `/`, or a domain. Only a guard that reads the cookie sets it, so a
     * guard that does not is never held to this.
     *
     * @param  string  $guard
     * @param  bool  $readsCookie
     * @param  string  $name
     * @param  ?string  $path
     * @param  ?string  $domain
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertHostCookie(string $guard, bool $readsCookie, string $name, ?string $path, ?string $domain): void
    {
        if ($readsCookie && str_starts_with($name, self::HOST_PREFIX) && ($path !== '/' || $domain !== null)) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.name', 'may start with `__Host-` only with `cookie.path` set to `/` and no `cookie.domain`'));
        }
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
     * The sources: a non-empty list of distinct source names.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>
     *
     * @throws \InvalidArgumentException
     */
    private static function sources(string $guard, mixed $value): array
    {
        $names   = is_array($value) && array_is_list($value) ? $value : [];
        $sources = array_map(static fn (mixed $source): ?RefreshTokenSource => RefreshTokenSource::tryFrom(is_string($source) ? $source : ''), $names);

        if ($sources === [] || in_array(null, $sources, true) || count(array_unique(array_column($sources, 'value'))) !== count($sources)) {
            throw new \InvalidArgumentException(self::message($guard, 'sources', 'must be a non-empty list of distinct sources: cookie, body, header'));
        }

        /** @var list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource> $sources */
        return $sources;
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
        if (!is_string($value) || preg_match(self::FIELD_PATTERN, $value) !== 1) {
            throw new \InvalidArgumentException(self::message($guard, 'body_field', 'must be a field name without `.`, spaces or brackets'));
        }

        return $value;
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
     * The cookie path: required when the cookie is a source, and a path when
     * set.
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
            throw new \InvalidArgumentException(self::message($guard, 'cookie.path', 'must be the path of the refresh route, starting with `/`, when the cookie is a source'));
        }

        return $value;
    }

    /**
     * The cookie domain: `null` for the request's host only, or a host name.
     *
     * @param  string  $guard
     * @param  mixed  $value
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function domain(string $guard, mixed $value): ?string
    {
        if ($value !== null && (!is_string($value) || preg_match(self::DOMAIN_PATTERN, $value) !== 1)) {
            throw new \InvalidArgumentException(self::message($guard, 'cookie.domain', 'must be null or a host name'));
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
