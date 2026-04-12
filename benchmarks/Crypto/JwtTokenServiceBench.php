<?php

declare(strict_types = 1);

namespace Benchmarks\Crypto;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Carbon\Carbon;
use Firebase\JWT\JWT;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * PHPBench suite for JWT token issue/parse paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @Warmup(1)
 */
final class JwtTokenServiceBench
{
    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $service;

    /** @var \Tests\Unit\Stubs\PlainIdentityFixture */
    private readonly PlainIdentityFixture $identity;

    /** @var \Tests\Unit\Stubs\PlainPrincipalFixture */
    private readonly PlainPrincipalFixture $principal;

    /** @var \Tests\Unit\Stubs\PlainDeviceFixture */
    private readonly PlainDeviceFixture $device;

    /** @var string Pre-issued access token for parse benchmarks. */
    private readonly string $accessToken;

    /**
     * Seed the JWT benchmark fixtures.
     */
    public function __construct()
    {
        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);
        JWT::$timestamp = $now->getTimestamp();

        $this->service = new JwtTokenService(
            'benchmark-jwt-secret-key-with-at-least-32-bytes!',
            'HS256',
            15,
            60 * 24 * 30,
        );

        $this->identity    = new PlainIdentityFixture('bench-identity');
        $this->principal   = new PlainPrincipalFixture('bench-principal', $this->identity);
        $this->device      = new PlainDeviceFixture('bench-device');
        $this->accessToken = $this->service->issueAccessToken($this->identity, $this->principal, $this->device);
    }

    /**
     * @Revs(100)
     *
     * @Iterations(5)
     */
    public function benchIssueAccessToken(): void
    {
        $this->service->issueAccessToken($this->identity, $this->principal, $this->device);
    }

    /**
     * @Revs(100)
     *
     * @Iterations(5)
     */
    public function benchParseAccessToken(): void
    {
        $this->service->parse($this->accessToken, TokenType::ACCESS);
    }
}
