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
     * Constructor stores the access token, when it expires, its lifetime and
     * the refresh token on the public properties.
     *
     * @return void
     */
    public function testConstructorStoresTheTokensAndTheAccessTokensExpiry(): void
    {
        $access  = new Secret('access-token');
        $refresh = new Secret('refresh-token');
        $expires = CarbonImmutable::createStrict(2026, 4, 6, 12, 5, 0);
        $result  = new TokenPair($access, $expires, 300, $refresh);

        self::assertSame($access, $result->accessToken);
        self::assertSame($expires, $result->expiresAt);
        self::assertSame(300, $result->expiresIn);
        self::assertSame($refresh, $result->refreshToken);
        self::assertNull($result->refreshCookie);
    }

    /**
     * An access token lives at least one second: a lifetime of one is taken,
     * none or a negative one is refused.
     *
     * @return void
     */
    public function testTheAccessTokenLivesAtLeastOneSecond(): void
    {
        $expires = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 1);

        self::assertSame(1, (new TokenPair(new Secret('access-token'), $expires, 1, new Secret('refresh-token')))->expiresIn);

        foreach ([0, -1] as $lifetime) {
            try {
                new TokenPair(new Secret('access-token'), $expires, $lifetime, new Secret('refresh-token'));

                self::fail('A pair took an access token that lives ' . $lifetime . ' seconds.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A token pair\'s access token lives at least one second.', $exception->getMessage());
            }
        }
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
        $result = new TokenPair(new Secret('access-token'), CarbonImmutable::now()->addMinutes(5), 300, null, $cookie);

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
        $cookie  = new RefreshCookie(new Secret('refresh-token'), '__Host-browser_refresh_token', '/', CarbonImmutable::now()->addDay());
        $expires = CarbonImmutable::now()->addMinutes(5);

        foreach ([[new Secret('refresh-token'), $cookie], [null, null]] as [$token, $carried]) {
            try {
                new TokenPair(new Secret('access-token'), $expires, 300, $token, $carried);

                self::fail('A pair carried its refresh token both ways, or neither.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A token pair carries its refresh token either in the body or in a cookie, never both or neither.', $exception->getMessage());
            }
        }
    }
}
