<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;
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
        'transport'  => 'body',
        'body_field' => 'refresh_token',
        'header'     => 'X-Refresh-Token',
        'cookie'     => [
            'name'            => null,
            'path'            => null,
            'allowed_origins' => [],
            'csrf_header'     => 'X-Requested-With',
        ],
    ];

    /**
     * A guard without a block of its own reads the package defaults: the body
     * transport, a `__Secure-` cookie name derived from the guard, and no
     * cookie path.
     *
     * @return void
     */
    public function testAGuardWithoutABlockReadsTheDefaults(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config(null));

        self::assertSame(Transport::BODY, $settings->transport);
        self::assertSame('refresh_token', $settings->bodyField);
        self::assertSame('X-Refresh-Token', $settings->header);
        self::assertSame('__Secure-api_refresh_token', $settings->cookieName);
        self::assertNull($settings->cookiePath);
        self::assertSame([], $settings->allowedOrigins);
        self::assertSame('X-Requested-With', $settings->csrfHeader);
    }

    /**
     * A key the guard sets wins over the package's, inside `cookie` too, and
     * the keys it leaves out keep the package's values; a cookie application
     * below the root path derives a `__Secure-` name.
     *
     * @return void
     */
    public function testTheGuardsKeysWinKeyByKey(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config([
            'transport' => 'cookie',
            'cookie'    => ['path' => '/auth', 'allowed_origins' => ['https://app.example.test', 'http://localhost:3000', 'http://[::1]:8080']],
        ]));

        self::assertSame(Transport::COOKIE, $settings->transport);
        self::assertSame('refresh_token', $settings->bodyField);
        self::assertSame('__Secure-api_refresh_token', $settings->cookieName);
        self::assertSame('/auth', $settings->cookiePath);
        self::assertSame(['https://app.example.test', 'http://localhost:3000', 'http://[::1]:8080'], $settings->allowedOrigins);
        self::assertSame('X-Requested-With', $settings->csrfHeader);
    }

    /**
     * A guard that overrides only some cookie keys keeps the package's others.
     *
     * @return void
     */
    public function testTheGuardsCookieKeysWinOneByOne(): void
    {
        $config = self::config(['cookie' => ['csrf_header' => 'X-CSRF']]);
        $config->set('authentication.refresh_token.cookie.name', '__Secure-shared');

        $settings = RefreshTokenSettings::forGuard('api', $config);

        self::assertSame('__Secure-shared', $settings->cookieName);
        self::assertSame('X-CSRF', $settings->csrfHeader);
        self::assertSame(Transport::BODY, $settings->transport);
    }

    /**
     * A guard whose `refresh_token` is `null` has no overrides, and a `null`
     * header reads the body field only.
     *
     * @return void
     */
    public function testANullBlockIsNoOverridesAndANullHeaderIsNone(): void
    {
        self::assertSame('X-Refresh-Token', RefreshTokenSettings::forGuard('api', self::config(null, true))->header);
        self::assertNull(RefreshTokenSettings::forGuard('api', self::config(['header' => null]))->header);
    }

    /**
     * Rows of `[the guard, its block, the cookie name it derives]`: an
     * application on the root path gets a `__Host-` name, every other one a
     * `__Secure-` name, each with the guard's own name in it.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: string}>
     */
    public static function provideDerivedNames(): iterable
    {
        yield 'a cookie application on the root path' => ['browser', ['transport' => 'cookie', 'cookie' => ['path' => '/']], '__Host-browser_refresh_token'];
        yield 'a cookie application below the root path' => ['browser', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']], '__Secure-browser_refresh_token'];
        yield 'a body application with a path' => ['mobile', ['cookie' => ['path' => '/']], '__Secure-mobile_refresh_token'];
        yield 'a body application' => ['mobile', [], '__Secure-mobile_refresh_token'];
        yield 'a guard whose name is a number' => ['2024', ['transport' => 'cookie', 'cookie' => ['path' => '/']], '__Host-2024_refresh_token'];
    }

    /**
     * Without a name of its own, an application's cookie is named after its
     * guard, so two applications on one host never share a cookie.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $block
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideDerivedNames')]
    public function testTheCookieNameIsDerivedFromTheApplication(string $guard, array $block, string $name): void
    {
        self::assertSame($name, RefreshTokenSettings::forGuard($guard, self::config($block, false, $guard))->cookieName);
    }

    /**
     * A guard whose name makes no cookie name (it holds a space, a separator or
     * another character a cookie name may not) needs a name of its own, and
     * fails closed without one; with one it is accepted.
     *
     * @return void
     */
    public function testAGuardNameThatMakesNoCookieNameNeedsAnExplicitOne(): void
    {
        foreach (['my app', 'app;x', 'app(x)'] as $guard) {
            try {
                RefreshTokenSettings::forGuard($guard, self::config([], false, $guard));

                self::fail("The guard [{$guard}] derived a cookie name.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(
                    "Refresh token transport for guard [{$guard}]: `refresh_token.cookie.name` must be set: the guard's name does not make a cookie name.",
                    $exception->getMessage(),
                );
            }
        }

        self::assertSame('__Secure-app', RefreshTokenSettings::forGuard('my app', self::config(['cookie' => ['name' => '__Secure-app']], false, 'my app'))->cookieName);
    }

    /**
     * An explicit `__Host-` cookie is accepted with `Path=/`, as a browser
     * requires to keep it, and for a body application, which never sets it,
     * whatever its path.
     *
     * @return void
     */
    public function testAnExplicitHostCookieIsAcceptedOnTheRootPath(): void
    {
        self::assertSame(
            '__Host-refresh',
            RefreshTokenSettings::forGuard('api', self::config(['transport' => 'cookie', 'cookie' => ['name' => '__Host-refresh', 'path' => '/']]))->cookieName,
        );
        self::assertSame('__Host-refresh', RefreshTokenSettings::forGuard('api', self::config(['cookie' => ['name' => '__Host-refresh', 'path' => '/auth']]))->cookieName);
    }

    /**
     * A body field, header or cookie name PHP keeps as it is in a request is
     * accepted, symbols included.
     *
     * @return void
     */
    public function testNamesPhpKeepsAreAccepted(): void
    {
        $settings = RefreshTokenSettings::forGuard('api', self::config([
            'body_field' => 'auth-refresh_token:1',
            'header'     => 'X_Refresh~Token',
            'cookie'     => ['name' => '$refresh+token%1', 'csrf_header' => 'X-CSRF!'],
        ]));

        self::assertSame('auth-refresh_token:1', $settings->bodyField);
        self::assertSame('X_Refresh~Token', $settings->header);
        self::assertSame('$refresh+token%1', $settings->cookieName);
        self::assertSame('X-CSRF!', $settings->csrfHeader);
    }

    /**
     * Two cookie applications whose cookie names are equal fail closed,
     * whichever is read, naming both guards: on one host they would overwrite
     * each other's cookie.
     *
     * @return void
     */
    public function testTwoCookieApplicationsWithOneNameFailClosed(): void
    {
        $config = self::config(['transport' => 'cookie', 'cookie' => ['name' => '__Secure-shared', 'path' => '/auth']]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['name' => '__Secure-shared', 'path' => '/admin']]]);

        foreach (['api' => 'admin', 'admin' => 'api'] as $guard => $other) {
            try {
                RefreshTokenSettings::forGuard($guard, $config);

                self::fail("The guard [{$guard}] shares its cookie.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(
                    "Refresh token transport for guard [{$guard}]: its refresh cookie `__Secure-shared` is also guard [{$other}]'s;"
                    . ' give one of them another `refresh_token.cookie.name`.',
                    $exception->getMessage(),
                );
            }
        }
    }

    /**
     * Cookie applications with derived names never collide, on any path; a
     * name another guard derives from the package-wide path is compared too;
     * and a body application, a non-`jwt` guard, or a guard whose transport is
     * malformed, that would share the name, is not a collision.
     *
     * @return void
     */
    public function testOnlyCookieApplicationsSharingANameCollide(): void
    {
        $config = self::config(['transport' => 'cookie', 'cookie' => ['path' => '/']]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/']]]);
        $config->set('auth.guards.mobile', ['driver' => 'jwt', 'refresh_token' => ['cookie' => ['name' => '__Host-api_refresh_token']]]);
        $config->set('auth.guards.web', ['driver' => 'session', 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['name' => '__Host-api_refresh_token']]]);
        $config->set('auth.guards.broken', ['driver' => 'jwt', 'refresh_token' => ['transport' => ['cookie'], 'cookie' => ['name' => '__Host-api_refresh_token']]]);

        self::assertSame('__Host-api_refresh_token', RefreshTokenSettings::forGuard('api', $config)->cookieName);
        self::assertSame('__Host-admin_refresh_token', RefreshTokenSettings::forGuard('admin', $config)->cookieName);

        $config->set('authentication.refresh_token.cookie.path', '/');
        $config->set('auth.guards.other', ['driver' => 'jwt', 'refresh_token' => ['transport' => 'cookie']]);
        $config->set('auth.guards.other_too', ['driver' => 'jwt', 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['name' => '__Host-other_refresh_token']]]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Refresh token transport for guard [other_too]: its refresh cookie `__Host-other_refresh_token` is also guard [other]\'s');

        RefreshTokenSettings::forGuard('other_too', $config);
    }

    /**
     * Rows of `[a CSRF header]` a cross-site form or simple request can carry
     * without the page setting it: CORS-safelisted, set by the browser itself,
     * or attached from cached credentials, in any letter case and with `_` for
     * `-`, which Symfony's header bag reads as the same header.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHeadersABrowserSendsOnItsOwn(): iterable
    {
        yield 'Accept' => ['Accept'];
        yield 'Accept-Language' => ['Accept-Language'];
        yield 'Content-Language' => ['Content-Language'];
        yield 'Content-Type' => ['Content-Type'];
        yield 'Range' => ['Range'];
        yield 'Origin' => ['Origin'];
        yield 'Cookie' => ['Cookie'];
        yield 'Referer' => ['Referer'];
        yield 'Host' => ['Host'];
        yield 'User-Agent' => ['User-Agent'];
        yield 'Authorization' => ['Authorization'];
        yield 'content-type in lower case' => ['content-type'];
        yield 'ORIGIN in upper case' => ['ORIGIN'];
        yield 'a Sec- header' => ['Sec-Fetch-Site'];
        yield 'a sec- header in lower case' => ['sec-ch-ua'];
        yield 'a Proxy- header' => ['Proxy-Authorization'];
        yield 'Content_Type with an underscore' => ['Content_Type'];
        yield 'User_Agent with an underscore' => ['User_Agent'];
        yield 'accept_language with an underscore in lower case' => ['accept_language'];
        yield 'a Sec_ header with an underscore' => ['Sec_Fetch_Site'];
        yield 'a PROXY_ header with an underscore in upper case' => ['PROXY_AUTHORIZATION'];
    }

    /**
     * A CSRF header a browser sends on its own proves nothing about the page
     * that sent the request, so it fails closed, naming the guard and the key.
     *
     * @param  string  $header
     * @return void
     */
    #[DataProvider('provideHeadersABrowserSendsOnItsOwn')]
    public function testACsrfHeaderABrowserSendsOnItsOwnFailsClosed(string $header): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Refresh token transport for guard [api]: `refresh_token.cookie.csrf_header` must be a custom header, not one a browser sends on its own.');

        RefreshTokenSettings::forGuard('api', self::config(['cookie' => ['csrf_header' => $header]]));
    }

    /**
     * A custom header is accepted as it is configured, even when it contains a
     * name a browser sends.
     *
     * @return void
     */
    public function testACustomCsrfHeaderIsAcceptedAsConfigured(): void
    {
        foreach (['X-Sec-Origin', 'X-Content-Type', 'Origin-Check', 'x-requested-with', 'X_Requested_With', 'Secret-Token', 'Sec'] as $header) {
            self::assertSame($header, RefreshTokenSettings::forGuard('api', self::config(['cookie' => ['csrf_header' => $header]]))->csrfHeader);
        }
    }

    /**
     * Rows of `[the guard's block, the message]`: each way a value is wrong.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedBlocks(): iterable
    {
        $path    = '`refresh_token.cookie.path` must be the path of the refresh route, starting with `/`, for a cookie application.';
        $origins = '`refresh_token.cookie.allowed_origins` must be a list of origins, each `scheme://host[:port]` in lower case.';
        $host    = '`refresh_token.cookie.name` may start with `__Host-` only with `cookie.path` set to `/`.';
        $field   = '`refresh_token.body_field` must be a field name without `.`, spaces or brackets.';
        $name    = 'must be a header or cookie name without `.`.';
        $mode    = '`refresh_token.transport` must be `body` or `cookie`.';

        yield 'a block that is not an array' => ['cookie', 'the guard\'s `refresh_token` must be an array.'];
        yield 'an unknown key' => [['source' => ['body']], 'the guard\'s `refresh_token` has an unknown key `source`.'];
        yield 'the sources of a list of carriers' => [['sources' => ['cookie']], 'the guard\'s `refresh_token` has an unknown key `sources`.'];
        yield 'a cookie block that is not an array' => [['cookie' => '/auth'], 'the guard\'s `refresh_token.cookie` must be an array.'];
        yield 'an unknown cookie key' => [['cookie' => ['secure' => false]], 'the guard\'s `refresh_token.cookie` has an unknown key `secure`.'];
        yield 'a cookie domain' => [['cookie' => ['domain' => 'example.test']], 'the guard\'s `refresh_token.cookie` has an unknown key `domain`.'];
        yield 'an unknown transport' => [['transport' => 'header'], $mode];
        yield 'a transport in upper case' => [['transport' => 'COOKIE'], $mode];
        yield 'a transport that is not a string' => [['transport' => ['cookie']], $mode];
        yield 'no transport' => [['transport' => null], $mode];
        yield 'an empty body field' => [['body_field' => ''], $field];
        yield 'a body field that is not a string' => [['body_field' => ['token']], $field];
        yield 'a body field with a dot' => [['body_field' => 'auth.refresh'], $field];
        yield 'a body field with a space' => [['body_field' => 'refresh token'], $field];
        yield 'a body field with a bracket' => [['body_field' => 'auth[refresh]'], $field];
        yield 'a body field with a closing bracket' => [['body_field' => 'refresh]'], $field];
        yield 'a body field with a control character' => [['body_field' => "refresh\x7F"], $field];
        yield 'a header that is not a name' => [['header' => 'X Refresh'], '`refresh_token.header` ' . $name];
        yield 'an empty header' => [['header' => ''], '`refresh_token.header` ' . $name];
        yield 'a header that is not a string' => [['header' => ['X-Refresh-Token']], '`refresh_token.header` ' . $name];
        yield 'a header with a dot' => [['header' => 'X.Refresh-Token'], '`refresh_token.header` ' . $name];
        yield 'a cookie name that is not a name' => [['cookie' => ['name' => 'refresh;token']], '`refresh_token.cookie.name` ' . $name];
        yield 'a cookie name with a dot' => [['cookie' => ['name' => 'app.refresh']], '`refresh_token.cookie.name` ' . $name];
        yield 'an empty cookie name' => [['cookie' => ['name' => '']], '`refresh_token.cookie.name` ' . $name];
        yield 'a CSRF header that is not a name' => [['cookie' => ['csrf_header' => '']], '`refresh_token.cookie.csrf_header` ' . $name];
        yield 'a CSRF header with a dot' => [['cookie' => ['csrf_header' => 'X.CSRF']], '`refresh_token.cookie.csrf_header` ' . $name];
        yield 'a CSRF header that is not a string' => [['cookie' => ['csrf_header' => ['X-CSRF']]], '`refresh_token.cookie.csrf_header` ' . $name];
        yield 'a cookie application without a path' => [['transport' => 'cookie'], $path];
        yield 'a path that is not absolute' => [['transport' => 'cookie', 'cookie' => ['path' => 'auth']], $path];
        yield 'a path with a separator' => [['transport' => 'cookie', 'cookie' => ['path' => '/auth;x']], $path];
        yield 'a malformed path on a body application' => [['cookie' => ['path' => 'auth']], $path];
        yield 'origins that are not a list' => [['cookie' => ['allowed_origins' => 'https://app.example.test']], $origins];
        yield 'origins that are not a sequential list' => [['cookie' => ['allowed_origins' => ['app' => 'https://app.example.test']]], $origins];
        yield 'an origin with a path' => [['cookie' => ['allowed_origins' => ['https://app.example.test/']]], $origins];
        yield 'an origin in upper case' => [['cookie' => ['allowed_origins' => ['https://App.example.test']]], $origins];
        yield 'an origin of another scheme' => [['cookie' => ['allowed_origins' => ['ftp://app.example.test']]], $origins];
        yield 'an origin without a host' => [['cookie' => ['allowed_origins' => ['https:///app']]], $origins];
        yield 'an origin with credentials' => [['cookie' => ['allowed_origins' => ['https://user@app.example.test']]], $origins];
        yield 'an origin that is not a string' => [['cookie' => ['allowed_origins' => [443]]], $origins];
        yield 'an origin after other text' => [['cookie' => ['allowed_origins' => ['xhttps://app.example.test']]], $origins];
        yield 'an origin with an empty port' => [['cookie' => ['allowed_origins' => ['https://app.example.test:']]], $origins];
        yield 'a body field with a trailing newline' => [['body_field' => "refresh_token\n"], $field];
        yield 'a header with a trailing newline' => [['header' => "X-Refresh-Token\n"], '`refresh_token.header` ' . $name];
        yield 'a cookie name with a trailing newline' => [['cookie' => ['name' => "refresh_token\n"]], '`refresh_token.cookie.name` ' . $name];
        yield 'a path with a trailing newline' => [['transport' => 'cookie', 'cookie' => ['path' => "/auth\n"]], $path];
        yield 'an origin with a trailing newline' => [['cookie' => ['allowed_origins' => ["https://app.example.test\n"]]], $origins];
        yield 'an explicit host cookie on another path' => [['transport' => 'cookie', 'cookie' => ['name' => '__Host-refresh', 'path' => '/auth']], $host];
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
     * The configuration of a guard (`api` unless named) with the given
     * `refresh_token` block (none when `null`, unless it is to be set to
     * `null`) over the package defaults.
     *
     * @param  mixed  $block
     * @param  bool  $setNull
     * @param  string  $name
     * @return \Illuminate\Config\Repository
     */
    private static function config(mixed $block, bool $setNull = false, string $name = 'api'): ConfigRepository
    {
        $guard = ['driver' => 'jwt', 'provider' => 'users'];

        if ($block !== null || $setNull) {
            $guard['refresh_token'] = $block;
        }

        return new ConfigRepository([
            'auth'           => ['guards' => [$name => $guard]],
            'authentication' => ['refresh_token' => self::DEFAULTS],
        ]);
    }
}
