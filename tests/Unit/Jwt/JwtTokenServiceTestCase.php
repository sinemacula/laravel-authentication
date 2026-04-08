<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Shared base case for the `JwtTokenService` split tests.
 *
 * Owns the frozen Carbon + JWT clocks, the test secret/algorithm/TTL
 * constants, and the helper factories used by every concrete
 * `JwtTokenServiceTest` variant. Subclasses focus on a single
 * behavioural slice (issuance, parse) so each derived class stays
 * well below the project's 20-method-per-class threshold (radarlint
 * S1448).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class JwtTokenServiceTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared secret used across the token-service tests. */
    protected const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm used by the service under test. */
    protected const string ALGORITHM = 'HS256';

    /** @var int Default access-token TTL in minutes. */
    protected const int ACCESS_TTL_MINUTES = 15;

    /** @var int Default refresh-token TTL in minutes. */
    protected const int REFRESH_TTL_MINUTES = 60 * 24 * 30;

    /** @var \Carbon\Carbon Frozen clock reference shared across token-time assertions. */
    protected Carbon $now;

    /**
     * Freeze both Carbon and the JWT library clock so expiry assertions
     * are deterministic and independent of wall time.
     *
     * @return void
     */
    #[\Override]
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
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Advance both the Carbon clock and the JWT library clock by the
     * supplied number of minutes so expiry assertions remain in sync.
     *
     * @param  int  $minutes
     * @return void
     */
    protected function advanceClock(int $minutes): void
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
    protected function makeService(): JwtTokenService
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
    protected function mockIdentity(string $id): Identity
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn($id);

        return $identity;
    }

    /**
     * Build a Principal mock whose getPrincipalIdentifier() returns
     * the supplied value.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    protected function mockPrincipal(string $id): Principal
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
    protected function mockDevice(string $id): Device
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device $device */
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')
            ->andReturn($id);

        return $device;
    }
}
