<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Unit tests for the JwtTokenService wrapper around firebase/php-jwt.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class JwtTokenServiceTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared secret used across the token-service tests. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm used by the service under test. */
    private const string ALGORITHM = 'HS256';

    /** @var int Default access-token TTL in minutes. */
    private const int ACCESS_TTL_MINUTES = 15;

    /** @var int Default refresh-token TTL in minutes. */
    private const int REFRESH_TTL_MINUTES = 60 * 24 * 30;

    /** @var \Carbon\Carbon Frozen clock reference shared across token-time assertions. */
    private Carbon $now;

    /**
     * Freeze both Carbon and the JWT library clock so expiry assertions
     * are deterministic and independent of wall time.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();
    }

    /**
     * Release both frozen clocks once each test has completed.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

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

    /**
     * Asserts parsing a token signed with a different secret returns
     * null rather than raising an exception.
     *
     * @return void
     */
    public function testParseReturnsNullOnInvalidSignature(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer   = $this->makeService();
        $verifier = new JwtTokenService('a-completely-different-secret-key-with-32!', self::ALGORITHM, self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES);

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token, Claims::TYPE_ACCESS));
    }

    /**
     * Asserts parsing a token whose `exp` claim has passed returns null.
     *
     * @return void
     */
    public function testParseReturnsNullOnExpiredToken(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();
        $token   = $service->issueAccessToken($identity, $principal, null);

        $this->advanceClock(self::ACCESS_TTL_MINUTES + 1);

        self::assertNull($service->parse($token, Claims::TYPE_ACCESS));
    }

    /**
     * A refresh token presented to `parse()` with `expectedType =
     * access` is rejected — the `typ` check prevents token-type
     * confusion.
     *
     * @return void
     */
    public function testParseRejectsRefreshTokenWhenAccessTypeIsExpected(): void
    {
        $device = $this->mockDevice('device-42');

        $service = $this->makeService();
        $token   = $service->issueRefreshToken($device, 'rotation-id');

        self::assertNull($service->parse($token, Claims::TYPE_ACCESS));
    }

    /**
     * An access token presented to `parse()` with `expectedType =
     * refresh` is rejected — the `typ` check prevents token-type
     * confusion.
     *
     * @return void
     */
    public function testParseRejectsAccessTokenWhenRefreshTypeIsExpected(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();
        $token   = $service->issueAccessToken($identity, $principal, null);

        self::assertNull($service->parse($token, Claims::TYPE_REFRESH));
    }

    /**
     * When the service is configured with an issuer and audience, a
     * token issued by that service parses cleanly on that service.
     *
     * @return void
     */
    public function testParseAcceptsIssuerAndAudienceOnMatchingService(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            'https://issuer.example.test',
            'https://audience.example.test',
        );

        $token  = $service->issueAccessToken($identity, $principal, null);
        $claims = $service->parse($token, Claims::TYPE_ACCESS);

        self::assertIsArray($claims);
        self::assertSame('https://issuer.example.test', $claims[Claims::ISSUER]);
        self::assertSame('https://audience.example.test', $claims[Claims::AUDIENCE]);
    }

    /**
     * A token whose issuer claim does not match the verifier's
     * configured issuer is rejected.
     *
     * @return void
     */
    public function testParseRejectsTokenWithMismatchedIssuer(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            'https://issuer-a.example.test',
        );

        $verifier = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            'https://issuer-b.example.test',
        );

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token, Claims::TYPE_ACCESS));
    }

    /**
     * Clock-skew leeway lets a token that is at most
     * `leewaySeconds` past its `exp` still decode cleanly.
     *
     * @return void
     */
    public function testParseAppliesLeewayWindow(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            1,
            self::REFRESH_TTL_MINUTES,
            30,
        );

        $token = $service->issueAccessToken($identity, $principal, null);

        // Advance past exp but within the 30-second leeway window.
        $advanced = $this->now->copy()->addSeconds(65);
        Carbon::setTestNow($advanced);
        JWT::$timestamp = $advanced->getTimestamp();

        $claims = $service->parse($token, Claims::TYPE_ACCESS);

        self::assertIsArray($claims);
    }

    /**
     * Advance both the Carbon clock and the JWT library clock by the
     * supplied number of minutes so expiry assertions remain in sync.
     *
     * @param  int  $minutes
     * @return void
     */
    private function advanceClock(int $minutes): void
    {
        $advanced = $this->now->copy()->addMinutes($minutes);

        Carbon::setTestNow($advanced);

        JWT::$timestamp = $advanced->getTimestamp();
    }

    /**
     * Build a JwtTokenService instance configured with the test
     * defaults.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeService(): JwtTokenService
    {
        return new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
        );
    }

    /**
     * Build an Identity mock whose getAuthIdentifier() returns the
     * supplied value.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function mockIdentity(string $id): Identity
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn($id);

        return $identity;
    }

    /**
     * Build a Principal mock whose getPrincipalIdentifier() returns the
     * supplied value.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function mockPrincipal(string $id): Principal
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn($id);

        return $principal;
    }

    /**
     * Build a Device mock whose getDeviceIdentifier() returns the
     * supplied value.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Device
     */
    private function mockDevice(string $id): Device
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device $device */
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')
            ->andReturn($id);

        return $device;
    }
}
