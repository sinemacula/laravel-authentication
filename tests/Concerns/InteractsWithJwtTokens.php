<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Firebase\JWT\JWT;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Shared JWT helpers for test cases that issue tokens and inspect what the
 * issuer wrote into the header.
 *
 * A trait rather than a base-class method because the JWT tests extend
 * different base cases (plain PHPUnit, Testbench, and the package `TestCase`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithJwtTokens
{
    /**
     * Decode the JWT header segment of the supplied token without verifying it,
     * so assertions on the header do not depend on the verifier path.
     *
     * @param  string  $token
     * @return array<array-key, mixed>
     */
    protected function jwtHeader(string $token): array
    {
        $segments = explode('.', $token);

        self::assertCount(3, $segments, 'JWT must have three segments');

        $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

        self::assertIsArray($header);

        return $header;
    }

    /**
     * Issue an access token for mock identity, principal, and device context
     * objects.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return string
     *
     * @throws \Random\RandomException
     */
    protected function issueAccessToken(JwtTokenService $service): string
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('id-1');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('pid-1');

        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')->andReturn('did-1');

        return $service->issueAccessToken($identity, $principal, $device);
    }
}
