<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use Tests\Concerns\InteractsWithJwtTokens;

/**
 * Key rotation tests for `JwtTokenService`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceKidTest extends JwtTokenServiceTestCase
{
    use InteractsWithJwtTokens;

    /** @var string Secret material for the previous-generation kid. */
    private const string OLD_SECRET = 'old-rotation-secret-with-32-bytes!!';

    /** @var string Secret material for the current-generation kid. */
    private const string NEW_SECRET = 'new-rotation-secret-with-32-bytes!!';

    /** @var string Kid used by the previous-generation key. */
    private const string OLD_KID = '2026-03';

    /** @var string Kid used by the current-generation key. */
    private const string NEW_KID = '2026-04';

    /**
     * An issued token embeds the active kid in its JWT header.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuedTokenEmbedsActiveKidInHeader(): void
    {
        $service = $this->makeKidService(
            [self::NEW_KID => self::NEW_SECRET],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $service->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertSame(self::NEW_KID, $this->jwtHeader($token)['kid'] ?? null);
    }

    /**
     * A token signed under an old kid parses while that kid is still in the
     * verification map.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseAcceptsTokenSignedWithOldKidDuringRotation(): void
    {
        $oldOnlyService = $this->makeKidService(
            [self::OLD_KID => self::OLD_SECRET],
            self::OLD_KID,
        );

        $rotatedService = $this->makeKidService(
            [
                self::NEW_KID => self::NEW_SECRET,
                self::OLD_KID => self::OLD_SECRET,
            ],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $oldOnlyService->issueAccessToken($identity, $principal, null, null)->reveal();

        $claims = $rotatedService->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims[Claims::SUBJECT->value]);
    }

    /**
     * A token signed under a kid the verifier does not know is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsTokenSignedWithRetiredKid(): void
    {
        $retiredOnlyService = $this->makeKidService(
            [self::OLD_KID => self::OLD_SECRET],
            self::OLD_KID,
        );

        $newOnlyService = $this->makeKidService(
            [self::NEW_KID => self::NEW_SECRET],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $retiredOnlyService->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertNull($newOnlyService->parse($token, TokenType::ACCESS));
    }

    /**
     * The default test service embeds its kid in every issued token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDefaultServiceEmbedsItsKidInHeader(): void
    {
        $service = $this->makeService();

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $service->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertSame(self::KID, $this->jwtHeader($token)['kid'] ?? null);
    }

    /**
     * A token without a `kid` header is rejected.
     *
     * @return void
     */
    public function testParseRejectsTokenWithoutKidHeader(): void
    {
        $token = JWT::encode(
            [
                Claims::ISSUER->value       => self::ISSUER,
                Claims::AUDIENCE->value     => self::AUDIENCE,
                Claims::CLIENT_ID->value    => self::GUARD,
                Claims::SUBJECT->value      => 'identity-7',
                Claims::SUBJECT_TYPE->value => 'person',
                Claims::PRINCIPAL->value    => 'principal-3',
                Claims::JWT_ID->value       => 'token-id',
                Claims::ISSUED_AT->value    => $this->now->getTimestamp(),
                Claims::EXPIRES_AT->value   => $this->now->getTimestamp() + 600,
            ],
            self::SECRET,
            self::ALGORITHM,
            null,
            ['typ' => TokenType::ACCESS->value],
        );

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
    }

    /**
     * Build a `JwtTokenService` over a keyring of the given keys and active
     * kid.
     *
     * @param  array<string, string>  $keys
     * @param  string  $activeKid
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeKidService(array $keys, string $activeKid): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap($keys, $activeKid, self::ALGORITHM),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );
    }
}
