<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Authentication\Http\RefreshCookie;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for the cookie that carries a cookie application's refresh token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshCookie::class)]
final class RefreshCookieTest extends TestCase
{
    /** @var string The refresh token the cookie carries. */
    private const string TOKEN = 'eyJhbGciOiJIUzI1NiJ9.refresh-payload.signature';

    /**
     * The cookie carries the token `HttpOnly`, `Secure`, `SameSite=Strict` and
     * host-only.
     *
     * @return void
     */
    public function testTheCookieCarriesTheTokenAsTheBrowserKeepsIt(): void
    {
        $expires = CarbonImmutable::createStrict(2026, 5, 6, 12, 0, 0);
        $refresh = self::refreshCookie($expires);
        $cookie  = $refresh->cookie();

        self::assertSame(['__Host-browser_refresh_token', '/', $expires], [$refresh->name, $refresh->path, $refresh->expiresAt]);
        self::assertSame('__Host-browser_refresh_token', $cookie->getName());
        self::assertSame(self::TOKEN, $cookie->getValue());
        self::assertSame('/', $cookie->getPath());
        self::assertNull($cookie->getDomain());
        self::assertSame($expires->getTimestamp(), $cookie->getExpiresTime());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertFalse($cookie->isRaw());
        self::assertFalse($cookie->isPartitioned());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
    }

    /**
     * Attaching the cookie adds it to the response and marks the response not
     * to be stored.
     *
     * @return void
     */
    public function testAttachingSetsTheCookieAndNoStore(): void
    {
        $response = (new JsonResponse(['access_token' => 'shown']))->setPublic()->setMaxAge(600);
        $attached = self::refreshCookie()->attachTo($response);

        self::assertSame($response, $attached);
        self::assertSame(['__Host-browser_refresh_token'], array_map(static fn (Cookie $cookie): string => $cookie->getName(), $attached->headers->getCookies()));
        self::assertSame(self::TOKEN, $attached->headers->getCookies()[0]->getValue());
        self::assertTrue($attached->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($attached->headers->hasCacheControlDirective('public'));
        self::assertSame('no-cache', $attached->headers->get('Pragma'));
        self::assertStringNotContainsString(self::TOKEN, (string) $attached->getContent());
    }

    /**
     * No dump of the cookie shows the token, and serialising it throws.
     *
     * @return void
     */
    public function testTheTokenIsShownByNoDumpAndNotSerialised(): void
    {
        $refresh = self::refreshCookie();

        $dumps = [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($refresh), true),
            print_r($refresh, true),
            var_export($refresh, true),
        ];

        foreach ($dumps as $dumped) {
            self::assertStringNotContainsString(self::TOKEN, $dumped);
            self::assertStringContainsString('__Host-browser_refresh_token', $dumped);
        }

        $this->expectException(SecretNotRevealedException::class);

        serialize($refresh);
    }

    /**
     * A cookie for the browser application's root path, expiring when given.
     *
     * @param  ?\Carbon\CarbonImmutable  $expires
     * @return \SineMacula\Laravel\Authentication\Http\RefreshCookie
     */
    private static function refreshCookie(?CarbonImmutable $expires = null): RefreshCookie
    {
        return new RefreshCookie(new Secret(self::TOKEN), '__Host-browser_refresh_token', '/', $expires ?? CarbonImmutable::now()->addDay());
    }
}
