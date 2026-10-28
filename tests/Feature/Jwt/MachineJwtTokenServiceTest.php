<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Models\Device as DeviceModel;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareDevice;

/**
 * Feature tests holding the token service to issuing no session token to a
 * non-human identity: no access token for one, and no refresh token for a
 * device one owns or for one as the principal, while human sessions are issued
 * as before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class MachineJwtTokenServiceTest extends TestCase
{
    /** @var string The refusal every machine gets. */
    private const string REFUSAL = 'A non-human identity has no session: it gets access tokens only from a client credentials exchange.';

    /**
     * No access token is issued to a machine, with or without a device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesNoAccessTokenToAMachine(): void
    {
        $machine = self::machine();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->tokens()->issueAccessToken($machine, $machine, null);
    }

    /**
     * No refresh token is issued for a device a machine owns, nor with a
     * machine as the principal; a human's device, plain or Eloquent, gets one.
     *
     * @return void
     */
    public function testIssuesNoRefreshTokenForAMachine(): void
    {
        $tokens  = $this->tokens();
        $machine = self::machine();
        $human   = self::device(IntegrationIdentity::class);

        foreach ([[self::device(MachineClient::class), null], [$human, $machine]] as [$device, $principal]) {
            try {
                $tokens->issueRefreshToken($device, 'rotation-id', $principal);

                self::fail('Expected the token service to refuse the machine.');
            } catch (\LogicException $exception) {
                self::assertSame(self::REFUSAL, $exception->getMessage());
            }
        }

        $plain = \Mockery::mock(Device::class);
        $plain->shouldReceive('getDeviceIdentifier')->andReturn('plain');
        $plain->shouldReceive('getIdleExpiresAt')->andReturn(CarbonImmutable::now()->addDay());
        $plain->shouldReceive('getAbsoluteExpiresAt')->andReturn(CarbonImmutable::now()->addDays(2));

        self::assertNotSame('', $tokens->issueRefreshToken($human, 'rotation-id', (new IntegrationIdentity)->forceFill(['id' => 7])));
        self::assertNotSame('', $tokens->issueRefreshToken($plain, 'rotation-id'));
    }

    /**
     * A device that is a model but not the package's Eloquent device records no
     * owner the service can read, so only its own state decides: here, its
     * missing deadlines.
     *
     * @return void
     */
    public function testAModelDeviceThatRecordsNoOwnerIsJudgedByItsState(): void
    {
        $device = (new StubBareDevice)->forceFill(['id' => 'bare']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        $this->tokens()->issueRefreshToken($device, 'rotation-id');
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        config()->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);

        return Auth::manager()->jwt('api');
    }

    /**
     * An unsaved machine client with a key.
     *
     * @return \Tests\Integration\Fixtures\MachineClient
     */
    private static function machine(): MachineClient
    {
        return (new MachineClient)->forceFill(['id' => 7]);
    }

    /**
     * A live device row recording an owner of the class.
     *
     * @param  class-string  $owner
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private static function device(string $owner): DeviceModel
    {
        return (new DeviceModel)->forceFill([
            'id'                   => 'device-1',
            'authenticatable_type' => $owner,
            'authenticatable_id'   => '7',
            'idle_expires_at'      => CarbonImmutable::now()->addDay(),
            'absolute_expires_at'  => CarbonImmutable::now()->addDays(2),
        ]);
    }
}
