<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Parse-side unit tests for `JwtTokenService` - `parse()` and the issuer /
 * audience / `typ` / leeway / logger surface.
 *
 * Split out of the original `JwtTokenServiceTest` so each class stays focused
 * on a single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceParseTest extends JwtTokenServiceTestCase
{
    /** @var string Test issuer URL used by the issuer-mismatch test. */
    private const string ISSUER_A = 'https://issuer-a.example.test';

    /** @var string Second test issuer URL used by the issuer-mismatch test. */
    private const string ISSUER_B = 'https://issuer-b.example.test';

    /**
     * Asserts parsing a token signed with a different secret returns null
     * rather than raising an exception.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseReturnsNullOnInvalidSignature(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer   = $this->makeService();
        $verifier = new JwtTokenService('a-completely-different-secret-key-with-32!', self::ALGORITHM, self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES);

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * Asserts parsing a token whose `exp` claim has passed returns null.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseReturnsNullOnExpiredToken(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();
        $token   = $service->issueAccessToken($identity, $principal, null);

        $this->advanceClock(self::ACCESS_TTL_MINUTES + 1);

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * A refresh token presented to `parse()` with `expectedType = access` is
     * rejected - the `typ` check prevents token-type confusion.
     *
     * @return void
     */
    public function testParseRejectsRefreshTokenWhenAccessTypeIsExpected(): void
    {
        $device = $this->mockDevice('device-42');

        $service = $this->makeService();
        $token   = $service->issueRefreshToken($device, 'rotation-id');

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * An access token presented to `parse()` with `expectedType = refresh` is
     * rejected - the `typ` check prevents token-type confusion.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsAccessTokenWhenRefreshTypeIsExpected(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();
        $token   = $service->issueAccessToken($identity, $principal, null);

        self::assertNull($service->parse($token, TokenType::REFRESH));
    }

    /**
     * When the service is configured with an issuer and audience, a token
     * issued by that service parses cleanly on that service.
     *
     * @return void
     *
     * @throws \Random\RandomException
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
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('https://issuer.example.test', $claims[Claims::ISSUER->value]);
        self::assertSame('https://audience.example.test', $claims[Claims::AUDIENCE->value]);
    }

    /**
     * A token whose issuer claim does not match the verifier's configured
     * issuer is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
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
            self::ISSUER_A,
        );

        $verifier = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            self::ISSUER_B,
        );

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A token whose audience claim does not match the verifier's configured
     * audience is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsTokenWithMismatchedAudience(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            null,
            'https://audience-a.example.test',
        );

        $verifier = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            null,
            'https://audience-b.example.test',
        );

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * Clock-skew leeway lets a token that is at most `leewaySeconds` past its
     * `exp` still decode cleanly.
     *
     * @return void
     *
     * @throws \Random\RandomException
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

        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
    }

    /**
     * After `parse()` returns, `JWT::$leeway` is restored to whatever value the
     * consumer had set before the call - not hard-reset to `0`. This regression
     * guards against the package clobbering consumer-configured clock-skew
     * tolerance across our decode window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRestoresPreviousLeewayAfterDecode(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        JWT::$leeway = 99;

        try {
            $service = new JwtTokenService(
                self::SECRET,
                self::ALGORITHM,
                self::ACCESS_TTL_MINUTES,
                self::REFRESH_TTL_MINUTES,
                15,
            );

            $token  = $service->issueAccessToken($identity, $principal, null);
            $claims = $service->parse($token, TokenType::ACCESS);

            self::assertIsArray($claims);
            self::assertSame(99, JWT::$leeway);
        } finally {
            JWT::$leeway = 0;
        }
    }

    /**
     * When a PSR-3 logger is supplied to the constructor, parse failures are
     * debug-logged with the underlying exception class so consumer error
     * reporters can attribute the failure mode.
     *
     * @return void
     */
    public function testParseDebugLogsFailureWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT decode failed', \Mockery::on(static fn (mixed $context): bool => is_array($context) && isset($context['exception'], $context['reason'])));

        $service = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            null,
            null,
            $logger,
        );

        self::assertNull($service->parse('not-a-jwt'));
    }

    /**
     * Issuer-mismatch failures are also debug-logged with the expected vs
     * received issuer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseDebugLogsIssuerMismatchWhenLoggerSupplied(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $issuer = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            self::ISSUER_A,
        );

        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with(
                'JWT issuer mismatch',
                \Mockery::on(static fn (mixed $context): bool => is_array($context)
                    && ($context['expected'] ?? null) === self::ISSUER_B),
            );

        $verifier = new JwtTokenService(
            self::SECRET,
            self::ALGORITHM,
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
            30,
            self::ISSUER_B,
            null,
            $logger,
        );

        $token = $issuer->issueAccessToken($identity, $principal, null);

        self::assertNull($verifier->parse($token));
    }
}
