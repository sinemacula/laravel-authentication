<?php

declare(strict_types = 1);

namespace Benchmarks\Crypto;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * PHPBench suite for JWT token issue and parse paths.
 *
 * Measures the raw cryptographic cost of HS256 token issuance and verification
 * without any guard or provider overhead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final readonly class JwtTokenServiceBench
{
    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private JwtTokenService $service;

    /** @var \Tests\Unit\Stubs\PlainIdentityFixture */
    private PlainIdentityFixture $identity;

    /** @var \Tests\Unit\Stubs\PlainPrincipalFixture */
    private PlainPrincipalFixture $principal;

    /** @var \Tests\Unit\Stubs\PlainDeviceFixture */
    private PlainDeviceFixture $device;

    /** @var string Pre-issued access token for parse benchmarks. */
    private string $accessToken;

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
     * Benchmark access token issuance (HS256 sign).
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(100)]
    public function benchIssueAccessToken(): void
    {
        $this->service->issueAccessToken($this->identity, $this->principal, $this->device);
    }

    /**
     * Benchmark access token parsing (HS256 verify + decode).
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(100)]
    public function benchParseAccessToken(): void
    {
        $this->service->parse($this->accessToken, TokenType::ACCESS);
    }
}
