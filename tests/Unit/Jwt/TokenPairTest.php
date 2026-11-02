<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\RefreshCookie;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Unit tests for the TokenPair value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenPair::class)]
final class TokenPairTest extends TestCase
{
    /**
     * Constructor stores the access and refresh tokens on the public
     * properties.
     *
     * @return void
     */
    public function testConstructorStoresAccessAndRefreshTokens(): void
    {
        $access  = new Secret('access-token');
        $refresh = new Secret('refresh-token');
        $result  = new TokenPair($access, $refresh);

        self::assertSame($access, $result->accessToken);
        self::assertSame($refresh, $result->refreshToken);
        self::assertNull($result->refreshCookie);
    }

    /**
     * A cookie application's pair carries the cookie in place of the refresh
     * token.
     *
     * @return void
     */
    public function testACookiePairCarriesTheCookieInsteadOfTheToken(): void
    {
        $cookie = new RefreshCookie(new Secret('refresh-token'), '__Host-browser_refresh_token', '/', CarbonImmutable::now()->addDay());
        $result = new TokenPair(new Secret('access-token'), null, $cookie);

        self::assertNull($result->refreshToken);
        self::assertSame($cookie, $result->refreshCookie);
    }

    /**
     * A pair carries its refresh token one way exactly: never both in the body
     * and in a cookie, nor neither.
     *
     * @return void
     */
    public function testAPairCarriesItsRefreshTokenOneWayExactly(): void
    {
        $cookie = new RefreshCookie(new Secret('refresh-token'), '__Host-browser_refresh_token', '/', CarbonImmutable::now()->addDay());

        foreach ([[new Secret('refresh-token'), $cookie], [null, null]] as [$token, $carried]) {
            try {
                new TokenPair(new Secret('access-token'), $token, $carried);

                self::fail('A pair carried its refresh token both ways, or neither.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A token pair carries its refresh token either in the body or in a cookie, never both or neither.', $exception->getMessage());
            }
        }
    }
}
