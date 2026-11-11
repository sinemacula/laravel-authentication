<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Firebase\JWT\JWT;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Shared JWT helpers for test cases that issue tokens and inspect their header.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithJwtTokens
{
    /**
     * Decode the header segment of the token without verifying it.
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
     * Issue a sessionless access token for a mock identity and a principal
     * within no tenant.
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
        $principal->shouldReceive('getTenant')->andReturn(null);

        return $service->issueAccessToken($identity, $principal, null, null)->reveal();
    }
}
