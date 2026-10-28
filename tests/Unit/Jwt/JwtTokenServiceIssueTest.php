<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Issuance-side unit tests for `JwtTokenService` - `issueAccessToken()` and
 * `issueRefreshToken()`.
 *
 * Split out of the original `JwtTokenServiceTest` so each class stays focused
 * on a single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceIssueTest extends JwtTokenServiceTestCase
{
    /**
     * Asserts an issued access token decodes back to the supplied identity,
     * principal, and device claims with an `exp` claim `access_ttl_minutes` in
     * the future and `typ = access`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenReturnsParseableJwt(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');
        $device    = $this->mockDevice('device-42');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, $device);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims[Claims::SUBJECT->value]);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL_ID->value]);
        self::assertSame('device-42', $claims[Claims::DEVICE_ID->value]);
        self::assertSame(TokenType::ACCESS->value, $claims[Claims::TYPE->value]);
        self::assertSame($this->now->getTimestamp(), $claims[Claims::ISSUED_AT->value]);
        self::assertSame($this->now->getTimestamp() + (self::ACCESS_TTL_MINUTES * 60), $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * Every issued access token carries a `jti` claim - the unique token
     * identifier that consumers can layer an external revocation denylist
     * against.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenIncludesJtiClaim(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $first  = $service->parse($service->issueAccessToken($identity, $principal, null), TokenType::ACCESS);
        $second = $service->parse($service->issueAccessToken($identity, $principal, null), TokenType::ACCESS);

        self::assertIsArray($first);
        self::assertIsArray($second);
        self::assertIsString($first[Claims::JWT_ID->value]);
        self::assertIsString($second[Claims::JWT_ID->value]);
        self::assertNotSame($first[Claims::JWT_ID->value], $second[Claims::JWT_ID->value], 'Each access token should carry a fresh jti.');
    }

    /**
     * An integer identifier returned by `getAuthIdentifier()` is stringified in
     * the `sub` claim per RFC 7519 §4.1.2.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenStringifiesIntegerSubjectClaim(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(42);

        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('42', $claims[Claims::SUBJECT->value]);
    }

    /**
     * Asserts issuing an access token without a device produces a token whose
     * `did` claim is explicitly present with a null value, so downstream
     * consumers see "no device hint" rather than a shape change.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenWithoutDeviceSetsNullDeviceClaim(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertArrayHasKey(Claims::DEVICE_ID->value, $claims);
        self::assertNull($claims[Claims::DEVICE_ID->value]);
    }

    /**
     * Asserts the refresh-token claims contain the device identifier, the
     * supplied rotation id (`jti`), and an `exp` claim `refresh_ttl_minutes` in
     * the future. Legacy refresh tokens still omit `pid`.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesDeviceAndRotationId(): void
    {
        $device = $this->mockDevice('device-42');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($device, 'opaque-rotation-id');
        $claims = $service->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame('device-42', $claims[Claims::DEVICE_ID->value]);
        self::assertSame('opaque-rotation-id', $claims[Claims::JWT_ID->value]);
        self::assertArrayNotHasKey(Claims::PRINCIPAL_ID->value, $claims);
        self::assertSame(TokenType::REFRESH->value, $claims[Claims::TYPE->value]);
        self::assertSame($this->now->getTimestamp(), $claims[Claims::ISSUED_AT->value]);
        self::assertSame($this->now->getTimestamp() + (self::REFRESH_TTL_MINUTES * 60), $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * Refresh tokens may carry the active principal identifier so refresh can
     * preserve principal context across rotations.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesPrincipalIdWhenSupplied(): void
    {
        $device    = $this->mockDevice('device-42');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($device, 'opaque-rotation-id', $principal);
        $claims = $service->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame('device-42', $claims[Claims::DEVICE_ID->value]);
        self::assertSame('opaque-rotation-id', $claims[Claims::JWT_ID->value]);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL_ID->value]);
    }

    /**
     * Identifier values that cannot be written into a required claim: an
     * unsaved model's `null`, the empty string `parse()` reads as missing, and
     * values that are not scalar.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnusableIdentifiers(): iterable
    {
        yield from [
            'null'         => [null],
            'empty string' => [''],
            'array'        => [['id' => 7]],
            'object'       => [new \stdClass],
        ];
    }

    /**
     * An access token is not issued for an identity whose identifier cannot
     * become the `sub` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesAnIdentityWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `sub` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity($identifier), $this->mockPrincipal('principal-3'), null);
    }

    /**
     * An access token is not issued for a principal whose identifier cannot
     * become the `pid` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesAPrincipalWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `pid` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal($identifier), null);
    }

    /**
     * An access token issued with a device whose identifier cannot become the
     * `did` claim is refused rather than silently issued as device-less.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesADeviceWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `did` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), $this->mockDevice($identifier));
    }

    /**
     * A refresh token is not issued for a device whose identifier cannot become
     * the `did` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueRefreshTokenRefusesADeviceWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `did` claim');

        $this->makeService()->issueRefreshToken($this->mockDevice($identifier), 'opaque-rotation-id');
    }

    /**
     * A refresh token issued with a principal whose identifier cannot become
     * the `pid` claim is refused rather than silently issued without one, which
     * would refresh into the default principal.
     *
     * @param  mixed  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueRefreshTokenRefusesAPrincipalWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `pid` claim');

        $this->makeService()->issueRefreshToken($this->mockDevice('device-42'), 'opaque-rotation-id', $this->mockPrincipal($identifier));
    }

    /**
     * A refresh token is not issued with an empty rotation id, which would
     * leave the `jti` claim `parse()` requires empty.
     *
     * @return void
     */
    public function testIssueRefreshTokenRefusesAnEmptyRotationId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `jti` claim');

        $this->makeService()->issueRefreshToken($this->mockDevice('device-42'), '');
    }
}
