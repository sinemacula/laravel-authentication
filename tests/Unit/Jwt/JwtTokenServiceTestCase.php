<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Shared base case for the `JwtTokenService` split tests.
 *
 * Owns the frozen Carbon + JWT clocks, the test secret/algorithm/TTL constants,
 * and the helper factories used by every concrete `JwtTokenServiceTest`
 * variant. Subclasses focus on a single behavioural slice (issuance, parse) so
 * each class stays focused on a single concern.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class JwtTokenServiceTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared secret used across the token-service tests. */
    protected const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string Kid the shared secret is registered under. */
    protected const string KID = 'test-kid';

    /** @var string Guard the test services are bound to. */
    protected const string GUARD = 'api';

    /** @var string HMAC algorithm used by the service under test. */
    protected const string ALGORITHM = 'HS256';

    /** @var int Default access-token TTL in minutes. */
    protected const int ACCESS_TTL_MINUTES = 15;

    /** @var int Default idle session lifetime in minutes. */
    protected const int REFRESH_TTL_MINUTES = 60 * 24 * 30;

    /** @var int Default absolute session lifetime in minutes. */
    protected const int ABSOLUTE_TTL_MINUTES = 60 * 24 * 180;

    /** @var \Carbon\Carbon Frozen clock reference shared across token-time assertions. */
    protected Carbon $now;

    /**
     * Freeze both Carbon and the JWT library clock so expiry assertions are
     * deterministic and independent of wall time.
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
     * Advance both the Carbon clock and the JWT library clock by the supplied
     * number of minutes so expiry assertions remain in sync.
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
     * Build a JwtTokenService instance configured with the test defaults.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    protected function makeService(): JwtTokenService
    {
        return new JwtTokenService(
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES),
            30,
        );
    }

    /**
     * Build a single-key keyring holding the supplied secret under the shared
     * test kid.
     *
     * @param  string  $secret
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtKeyring
     */
    protected function makeKeyring(#[\SensitiveParameter] string $secret = self::SECRET): JwtKeyring
    {
        return JwtKeyring::fromKeyMap([self::KID => $secret], self::KID, self::ALGORITHM);
    }

    /**
     * Build an Identity mock whose getAuthIdentifier() returns the supplied
     * value.
     *
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    protected function mockIdentity(mixed $id): Identity
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
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    protected function mockPrincipal(mixed $id): Principal
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn($id);

        return $principal;
    }

    /**
     * Build a Device mock whose getDeviceIdentifier() returns the supplied
     * value, in a session that started now with the default lifetimes.
     *
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function mockDevice(mixed $id): Device
    {
        return $this->mockDeviceEndingAt($id, $this->now->copy()->addMinutes(self::REFRESH_TTL_MINUTES), $this->now->copy()->addMinutes(self::ABSOLUTE_TTL_MINUTES));
    }

    /**
     * Build a Device mock with the supplied identifier and deadlines.
     *
     * @param  mixed  $id
     * @param  ?\Carbon\CarbonInterface  $idle
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @return \SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function mockDeviceEndingAt(mixed $id, ?CarbonInterface $idle, ?CarbonInterface $absolute): Device
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device $device */
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')
            ->andReturn($id);
        $device->shouldReceive('getIdleExpiresAt')
            ->andReturn($idle);
        $device->shouldReceive('getAbsoluteExpiresAt')
            ->andReturn($absolute);

        return $device;
    }
}
