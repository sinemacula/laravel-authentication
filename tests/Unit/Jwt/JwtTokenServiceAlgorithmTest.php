<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Concerns\InteractsWithJwtTokens;

/**
 * Algorithm allow-list tests for `JwtTokenService`.
 *
 * Proves every allow-listed HMAC algorithm signs and verifies end to end: the
 * service signs under its keyring's algorithm, so a token issued over a keyring
 * for the algorithm carries it in the JWT header and parses back to the issued
 * claims.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtKeyring::class)]
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceAlgorithmTest extends JwtTokenServiceTestCase
{
    use InteractsWithJwtTokens;

    /** @var string Key material long enough for every allow-listed algorithm. */
    private const string LONG_SECRET = 'algorithm-round-trip-secret-with-at-least-sixty-four-bytes-of-key';

    /**
     * Data provider listing every allow-listed signing algorithm.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAllowedAlgorithms(): iterable
    {
        yield from [
            'HS256' => ['HS256'],
            'HS384' => ['HS384'],
            'HS512' => ['HS512'],
        ];
    }

    /**
     * Asserts a token issued over a keyring for each allow-listed algorithm
     * names that algorithm in its header and parses back to the issued claims.
     *
     * @param  string  $algorithm
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAllowedAlgorithms')]
    public function testIssuedTokenRoundTripsUnderAllowedAlgorithm(string $algorithm): void
    {
        $service = new JwtTokenService(
            JwtKeyring::fromKeyMap([self::KID => self::LONG_SECRET], self::KID, $algorithm),
            self::GUARD,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
        );

        $token = $service->issueAccessToken(
            $this->mockIdentity('identity-7'),
            $this->mockPrincipal('principal-3'),
            null,
        );

        self::assertSame($algorithm, $this->jwtHeader($token)['alg'] ?? null);

        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims[Claims::SUBJECT->value]);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL_ID->value]);
    }
}
