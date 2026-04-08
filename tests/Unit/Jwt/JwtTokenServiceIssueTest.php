<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Issuance-side unit tests for `JwtTokenService` —
 * `issueAccessToken()`, `issueRefreshToken()`, and the empty-secret
 * fail-loud constructor guard.
 *
 * Split out of the original `JwtTokenServiceTest` so each derived
 * class stays well below the project's 20-method-per-class
 * threshold (radarlint S1448).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceIssueTest extends JwtTokenServiceTestCase
{
    /**
     * The constructor refuses to build with an empty secret so the
     * package fails loudly on missing env vars instead of silently
     * signing tokens with a zero-knowledge key.
     *
     * @return void
     */
    public function testConstructorRejectsEmptySecret(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);

        $service = new JwtTokenService('', self::ALGORITHM, self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES);

        unset($service); // Constructor must throw before this point.
    }

    /**
     * Asserts an issued access token decodes back to the supplied
     * identity, principal, and device claims with an `exp` claim
     * `access_ttl_minutes` in the future and `typ = access`.
     *
     * @return void
     */
    public function testIssueAccessTokenReturnsParseableJwt(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');
        $device    = $this->mockDevice('device-42');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, $device);
        $claims = $service->parse($token, Claims::TYPE_ACCESS);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims[Claims::SUBJECT]);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL_ID]);
        self::assertSame('device-42', $claims[Claims::DEVICE_ID]);
        self::assertSame(Claims::TYPE_ACCESS, $claims[Claims::TYPE]);
        self::assertSame($this->now->getTimestamp(), $claims[Claims::ISSUED_AT]);
        self::assertSame($this->now->getTimestamp() + (self::ACCESS_TTL_MINUTES * 60), $claims[Claims::EXPIRES_AT]);
    }

    /**
     * Every issued access token carries a `jti` claim — the unique
     * token identifier that consumers can layer an external
     * revocation denylist against.
     *
     * @return void
     */
    public function testIssueAccessTokenIncludesJtiClaim(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $first  = $service->parse($service->issueAccessToken($identity, $principal, null), Claims::TYPE_ACCESS);
        $second = $service->parse($service->issueAccessToken($identity, $principal, null), Claims::TYPE_ACCESS);

        self::assertIsArray($first);
        self::assertIsArray($second);
        self::assertIsString($first[Claims::JWT_ID]);
        self::assertIsString($second[Claims::JWT_ID]);
        self::assertNotSame($first[Claims::JWT_ID], $second[Claims::JWT_ID], 'Each access token should carry a fresh jti.');
    }

    /**
     * An integer identifier returned by `getAuthIdentifier()` is
     * stringified in the `sub` claim per RFC 7519 §4.1.2.
     *
     * @return void
     */
    public function testIssueAccessTokenStringifiesIntegerSubjectClaim(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(42);

        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null);
        $claims = $service->parse($token, Claims::TYPE_ACCESS);

        self::assertIsArray($claims);
        self::assertSame('42', $claims[Claims::SUBJECT]);
    }

    /**
     * Asserts issuing an access token without a device produces a
     * token whose `did` claim is null.
     *
     * @return void
     */
    public function testIssueAccessTokenWithoutDeviceOmitsDeviceClaim(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null);
        $claims = $service->parse($token, Claims::TYPE_ACCESS);

        self::assertIsArray($claims);
        self::assertNull($claims[Claims::DEVICE_ID]);
    }

    /**
     * Asserts the refresh-token claims contain the device identifier,
     * the supplied rotation id (`jti`), and an `exp` claim
     * `refresh_ttl_minutes` in the future.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesDeviceAndRotationId(): void
    {
        $device = $this->mockDevice('device-42');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($device, 'opaque-rotation-id');
        $claims = $service->parse($token, Claims::TYPE_REFRESH);

        self::assertIsArray($claims);
        self::assertSame('device-42', $claims[Claims::DEVICE_ID]);
        self::assertSame('opaque-rotation-id', $claims[Claims::JWT_ID]);
        self::assertSame(Claims::TYPE_REFRESH, $claims[Claims::TYPE]);
        self::assertSame($this->now->getTimestamp(), $claims[Claims::ISSUED_AT]);
        self::assertSame($this->now->getTimestamp() + (self::REFRESH_TTL_MINUTES * 60), $claims[Claims::EXPIRES_AT]);
    }
}
