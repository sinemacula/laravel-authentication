<?php

declare(strict_types=1);

namespace Tests\Unit\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
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
    private const int TTL_MINUTES = 15;

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
     * Asserts an issued access token decodes back to the supplied
     * identity, principal, and device claims with an `exp` claim 15
     * minutes in the future.
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
        $claims = $service->parse($token);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims['sub']);
        self::assertSame('principal-3', $claims['pid']);
        self::assertSame('device-42', $claims['did']);
        self::assertSame($this->now->getTimestamp(), $claims['iat']);
        self::assertSame($this->now->getTimestamp() + (self::TTL_MINUTES * 60), $claims['exp']);
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
        $claims = $service->parse($token);

        self::assertIsArray($claims);
        self::assertNull($claims['did']);
    }

    /**
     * Asserts the refresh-token claims contain the device identifier
     * and the supplied plaintext refresh key.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesDeviceAndPlaintextKey(): void
    {
        $device = $this->mockDevice('device-42');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($device, 'plain-refresh-key');
        $claims = $service->parse($token);

        self::assertIsArray($claims);
        self::assertSame('device-42', $claims['did']);
        self::assertSame('plain-refresh-key', $claims['rk']);
        self::assertSame($this->now->getTimestamp(), $claims['iat']);
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
        $verifier = new JwtTokenService('a-completely-different-secret-key-with-32!', self::ALGORITHM, self::TTL_MINUTES);

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token));
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

        $this->advanceClock(self::TTL_MINUTES + 1);

        self::assertNull($service->parse($token));
    }

    /**
     * Asserts parseAllowingExpired() still returns the decoded claims
     * for a token whose `exp` claim has passed.
     *
     * @return void
     */
    public function testParseAllowingExpiredReturnsClaimsOnExpiredToken(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();
        $token   = $service->issueAccessToken($identity, $principal, null);

        $this->advanceClock(self::TTL_MINUTES + 1);

        $claims = $service->parseAllowingExpired($token);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims['sub']);
        self::assertSame('principal-3', $claims['pid']);
    }

    /**
     * Asserts parseAllowingExpired() returns null for a token signed
     * with a different secret — expiry tolerance does not extend to
     * signature tolerance.
     *
     * @return void
     */
    public function testParseAllowingExpiredReturnsNullOnInvalidSignature(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer   = $this->makeService();
        $verifier = new JwtTokenService('a-completely-different-secret-key-with-32!', self::ALGORITHM, self::TTL_MINUTES);

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parseAllowingExpired($token));
    }

    /**
     * Asserts parseAllowingExpired() returns null for a string that
     * does not contain three dot-separated segments.
     *
     * @return void
     */
    public function testParseAllowingExpiredReturnsNullForMalformedToken(): void
    {
        $service = $this->makeService();

        self::assertNull($service->parseAllowingExpired('not-a-jwt'));
    }

    /**
     * Advance both the Carbon clock and the JWT library clock by the
     * supplied number of minutes so expiry assertions remain in sync.
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
     */
    private function makeService(): JwtTokenService
    {
        return new JwtTokenService(self::SECRET, self::ALGORITHM, self::TTL_MINUTES);
    }

    /**
     * Build an Identity mock whose getAuthIdentifier() returns the
     * supplied value.
     */
    private function mockIdentity(string $id): Identity
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn($id);

        return $identity;
    }

    /**
     * Build a Principal mock whose getPrincipalIdentifier() returns the
     * supplied value.
     */
    private function mockPrincipal(string $id): Principal
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn($id);

        return $principal;
    }

    /**
     * Build a Device mock whose getDeviceIdentifier() returns the
     * supplied value.
     */
    private function mockDevice(string $id): Device
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device $device */
        $device = Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')
            ->andReturn($id);

        return $device;
    }
}
