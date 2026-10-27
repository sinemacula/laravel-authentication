<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Unit tests for the `grd` claim that binds every token to the guard whose
 * service issued it.
 *
 * Every service here shares one keyring, so a token from another guard is
 * signed with a key the verifier holds: only the guard claim rejects it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceGuardTest extends JwtTokenServiceTestCase
{
    /** @var string A second guard sharing the test keyring. */
    private const string OTHER_GUARD = 'admin';

    /**
     * Access and refresh tokens both carry the issuing guard's name.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuedTokensCarryTheIssuingGuard(): void
    {
        $service = $this->makeService();

        $access  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null), TokenType::ACCESS);
        $refresh = $service->parse($service->issueRefreshToken($this->mockDevice('device-42'), 'rotation-id'), TokenType::REFRESH);

        self::assertIsArray($access);
        self::assertIsArray($refresh);
        self::assertSame(self::GUARD, $access[Claims::GUARD->value]);
        self::assertSame(self::GUARD, $refresh[Claims::GUARD->value]);
    }

    /**
     * An access token issued for another guard with the same key is rejected,
     * whether or not a token type is expected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsAnAccessTokenIssuedForAnotherGuard(): void
    {
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null);

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($token));
        self::assertIsArray($this->makeServiceFor(self::OTHER_GUARD)->parse($token, TokenType::ACCESS));
    }

    /**
     * A refresh token issued for another guard with the same key is rejected.
     *
     * @return void
     */
    public function testParseRejectsARefreshTokenIssuedForAnotherGuard(): void
    {
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueRefreshToken($this->mockDevice('device-42'), 'rotation-id');

        self::assertNull($this->makeService()->parse($token, TokenType::REFRESH));
    }

    /**
     * A correctly signed token with every other claim but no `grd` is rejected.
     *
     * @return void
     */
    public function testParseRejectsATokenWithoutAGuardClaim(): void
    {
        $token = JWT::encode(
            [
                Claims::SUBJECT->value    => 'identity-7',
                Claims::ISSUED_AT->value  => $this->now->getTimestamp(),
                Claims::EXPIRES_AT->value => $this->now->getTimestamp() + 600,
                Claims::TYPE->value       => TokenType::ACCESS->value,
            ],
            self::SECRET,
            self::ALGORITHM,
            self::KID,
        );

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
    }

    /**
     * A guard mismatch is debug-logged with the expected and received guard.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseDebugLogsAGuardMismatchWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT guard mismatch', ['expected' => self::GUARD, 'received' => self::OTHER_GUARD]);

        $verifier = new JwtTokenService(
            $this->makeKeyring(),
            self::GUARD,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            null,
            null,
            $logger,
        );

        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null);

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A service cannot be built without a guard to bind its tokens to.
     *
     * @return void
     */
    public function testConstructorRejectsAnEmptyGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('JWT token service requires a non-empty guard name.');

        $this->makeServiceFor('');
    }

    /**
     * Build a service on the shared test keyring bound to the named guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeServiceFor(string $guard): JwtTokenService
    {
        return new JwtTokenService(
            $this->makeKeyring(),
            $guard,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
        );
    }
}
