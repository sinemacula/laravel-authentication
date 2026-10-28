<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;

/**
 * Unit tests for reading a guard's refresh token transport from its
 * `refresh_token` block over the package defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenSettings::class)]
final class RefreshTokenSettingsTest extends TestCase
{
    /** @var array<string, mixed> The package defaults, as the shipped configuration sets them. */
    private const array DEFAULTS = [
        'sources'    => ['body', 'header'],
        'body_field' => 'refresh_token',
        'header'     => 'X-Refresh-Token',
        'cookie'     => [
            'name'            => '__Secure-refresh_token',
            'path'            => null,
            'domain'          => null,
            'allowed_origins' => [],
            'csrf_header'     => 'X-Requested-With',
        ],
    ];

    /**
     * A guard without a block of its own reads the package defaults, and the
     * cookie is not scoped to a path while it is not a source.
     *
     * @return void
     */
    public function testAGuardWithoutABlockReadsTheDefaults(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config(null));

        self::assertSame([RefreshTokenSource::BODY, RefreshTokenSource::HEADER], $settings->sources);
        self::assertSame('refresh_token', $settings->bodyField);
        self::assertSame('X-Refresh-Token', $settings->header);
        self::assertSame('__Secure-refresh_token', $settings->cookieName);
        self::assertNull($settings->cookiePath);
        self::assertNull($settings->cookieDomain);
        self::assertSame([], $settings->allowedOrigins);
        self::assertSame('X-Requested-With', $settings->csrfHeader);
    }

    /**
     * A key the guard sets wins over the package's, inside `cookie` too, and
     * the keys it leaves out keep the package's values.
     *
     * @return void
     */
    public function testTheGuardsKeysWinKeyByKey(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config([
            'sources' => ['cookie'],
            'cookie'  => ['path' => '/auth', 'domain' => '.example.test', 'allowed_origins' => ['https://app.example.test', 'http://localhost:3000']],
        ]));

        self::assertSame([RefreshTokenSource::COOKIE], $settings->sources);
        self::assertSame('refresh_token', $settings->bodyField);
        self::assertSame('__Secure-refresh_token', $settings->cookieName);
        self::assertSame('/auth', $settings->cookiePath);
        self::assertSame('.example.test', $settings->cookieDomain);
        self::assertSame(['https://app.example.test', 'http://localhost:3000'], $settings->allowedOrigins);
        self::assertSame('X-Requested-With', $settings->csrfHeader);
    }

    /**
     * A guard whose `refresh_token` is `null` has no overrides.
     *
     * @return void
     */
    public function testANullBlockIsNoOverrides(): void
    {
        self::assertSame('X-Refresh-Token', RefreshTokenSettings::forGuard('api', self::config(null, true))->header);
    }

    /**
     * A `__Host-` cookie is accepted with `Path=/` and no domain, as a browser
     * requires to keep it.
     *
     * @return void
     */
    public function testAHostCookieIsAcceptedOnTheRootPathWithoutADomain(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config(['sources' => ['cookie'], 'cookie' => ['name' => '__Host-refresh', 'path' => '/']]));

        self::assertSame('__Host-refresh', $settings->cookieName);
    }

    /**
     * Rows of `[the guard's block, the message]`: each way a value is wrong.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedBlocks(): iterable
    {
        $sources = '`refresh_token.sources` must be a non-empty list of distinct sources: cookie, body, header.';
        $path    = '`refresh_token.cookie.path` must be the path of the refresh route, starting with `/`, when the cookie is a source.';
        $origins = '`refresh_token.cookie.allowed_origins` must be a list of origins, each `scheme://host[:port]` in lower case.';
        $host    = '`refresh_token.cookie.name` may start with `__Host-` only with `cookie.path` set to `/` and no `cookie.domain`.';

        yield 'a block that is not an array' => ['cookie', 'the guard\'s `refresh_token` must be an array.'];
        yield 'an unknown key' => [['source' => ['body']], 'the guard\'s `refresh_token` has an unknown key `source`.'];
        yield 'a cookie block that is not an array' => [['cookie' => '/auth'], 'the guard\'s `refresh_token.cookie` must be an array.'];
        yield 'an unknown cookie key' => [['cookie' => ['secure' => false]], 'the guard\'s `refresh_token.cookie` has an unknown key `secure`.'];
        yield 'no sources' => [['sources' => []], $sources];
        yield 'sources that are not a list' => [['sources' => ['a' => 'body']], $sources];
        yield 'sources that are not a list of names' => [['sources' => 'body'], $sources];
        yield 'an unknown source' => [['sources' => ['query']], $sources];
        yield 'a source that is not a string' => [['sources' => [1]], $sources];
        yield 'a source named twice' => [['sources' => ['body', 'body']], $sources];
        yield 'an empty body field' => [['body_field' => ''], '`refresh_token.body_field` must be a non-empty string.'];
        yield 'a body field that is not a string' => [['body_field' => ['token']], '`refresh_token.body_field` must be a non-empty string.'];
        yield 'a header that is not a name' => [['header' => 'X Refresh'], '`refresh_token.header` must be a header or cookie name.'];
        yield 'a header that is not a string' => [['header' => null], '`refresh_token.header` must be a header or cookie name.'];
        yield 'a cookie name that is not a name' => [['cookie' => ['name' => 'refresh;token']], '`refresh_token.cookie.name` must be a header or cookie name.'];
        yield 'a CSRF header that is not a name' => [['cookie' => ['csrf_header' => '']], '`refresh_token.cookie.csrf_header` must be a header or cookie name.'];
        yield 'a cookie source without a path' => [['sources' => ['cookie']], $path];
        yield 'a path that is not absolute' => [['sources' => ['cookie'], 'cookie' => ['path' => 'auth']], $path];
        yield 'a path with a separator' => [['sources' => ['cookie'], 'cookie' => ['path' => '/auth;x']], $path];
        yield 'a malformed path while the cookie is not a source' => [['cookie' => ['path' => 'auth']], $path];
        yield 'a domain that is not a host name' => [['cookie' => ['domain' => 'https://example.test']], '`refresh_token.cookie.domain` must be null or a host name.'];
        yield 'a domain that is not a string' => [['cookie' => ['domain' => true]], '`refresh_token.cookie.domain` must be null or a host name.'];
        yield 'origins that are not a list' => [['cookie' => ['allowed_origins' => 'https://app.example.test']], $origins];
        yield 'origins that are not a sequential list' => [['cookie' => ['allowed_origins' => ['app' => 'https://app.example.test']]], $origins];
        yield 'an origin with a path' => [['cookie' => ['allowed_origins' => ['https://app.example.test/']]], $origins];
        yield 'an origin in upper case' => [['cookie' => ['allowed_origins' => ['https://App.example.test']]], $origins];
        yield 'an origin of another scheme' => [['cookie' => ['allowed_origins' => ['ftp://app.example.test']]], $origins];
        yield 'an origin without a host' => [['cookie' => ['allowed_origins' => ['https:///app']]], $origins];
        yield 'an origin with credentials' => [['cookie' => ['allowed_origins' => ['https://user@app.example.test']]], $origins];
        yield 'an origin that is not a string' => [['cookie' => ['allowed_origins' => [443]]], $origins];
        yield 'a host cookie on another path' => [['sources' => ['cookie'], 'cookie' => ['name' => '__Host-refresh', 'path' => '/auth']], $host];
        yield 'a host cookie with a domain' => [['sources' => ['cookie'], 'cookie' => ['name' => '__Host-refresh', 'path' => '/', 'domain' => 'example.test']], $host];
    }

    /**
     * A malformed value or an unknown key fails closed, naming the guard and
     * the key.
     *
     * @param  mixed  $block
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedBlocks')]
    public function testAMalformedBlockFailsClosed(mixed $block, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Refresh token transport for guard [api]: ' . $message);

        RefreshTokenSettings::forGuard('api', self::config($block));
    }

    /**
     * Malformed package defaults fail closed as well, named as the package's.
     *
     * @return void
     */
    public function testMalformedDefaultsFailClosed(): void
    {
        $config = self::config(null);
        $config->set('authentication.refresh_token.cookie', ['same_site' => 'lax']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Refresh token transport for guard [api]: `authentication.refresh_token.cookie` has an unknown key `same_site`.');

        RefreshTokenSettings::forGuard('api', $config);
    }

    /**
     * A missing package block fails closed rather than reading as defaults.
     *
     * @return void
     */
    public function testMissingDefaultsFailClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Refresh token transport for guard [api]: `authentication.refresh_token` must be an array.');

        RefreshTokenSettings::forGuard('api', new ConfigRepository(['auth' => ['guards' => ['api' => ['driver' => 'jwt']]]]));
    }

    /**
     * A guard that is not configured is reported as such.
     *
     * @return void
     */
    public function testAGuardThatIsNotConfiguredIsReported(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [admin] is not configured.');

        RefreshTokenSettings::forGuard('admin', self::config(null));
    }

    /**
     * The configuration of an `api` guard with the given `refresh_token` block
     * (none when `null`, unless it is to be set to `null`) over the package
     * defaults.
     *
     * @param  mixed  $block
     * @param  bool  $setNull
     * @return \Illuminate\Config\Repository
     */
    private static function config(mixed $block, bool $setNull = false): ConfigRepository
    {
        $guard = ['driver' => 'jwt', 'provider' => 'users'];

        if ($block !== null || $setNull) {
            $guard['refresh_token'] = $block;
        }

        return new ConfigRepository([
            'auth'           => ['guards' => ['api' => $guard]],
            'authentication' => ['refresh_token' => self::DEFAULTS],
        ]);
    }
}
