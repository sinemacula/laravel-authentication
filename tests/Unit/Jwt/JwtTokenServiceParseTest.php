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
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Parse tests for `JwtTokenService`.
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
     * A token signed with a different secret parses to `null`.
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
        $verifier = new JwtTokenService(
            $this->makeKeyring('a-completely-different-secret-key-with-32!'),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );

        $token = $issuer->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A token whose `exp` has passed parses to `null`.
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
        $token   = $service->issueAccessToken($identity, $principal, null, null)->reveal();

        $this->advanceClock(self::ACCESS_TTL_MINUTES + 1);

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * A refresh token is rejected where an access token is expected.
     *
     * @return void
     */
    public function testParseRejectsRefreshTokenWhenAccessTypeIsExpected(): void
    {
        $session = $this->mockSession('session-42');

        $service = $this->makeService();
        $token   = $service->issueRefreshToken($session, 'rotation-id')->reveal();

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * An access token is rejected where a refresh token is expected.
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
        $token   = $service->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertNull($service->parse($token, TokenType::REFRESH));
    }

    /**
     * Every token carries the service's issuer and audience and parses on that
     * service.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseAcceptsIssuerAndAudienceOnMatchingService(): void
    {
        $service = $this->makeServiceWith(self::ISSUER_A, 'https://audience.example.test');

        foreach ([$this->accessToken($service), $service->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')->reveal()] as $token) {

            $claims = $service->parse($token);

            self::assertIsArray($claims);
            self::assertSame(self::ISSUER_A, $claims[Claims::ISSUER->value]);
            self::assertSame('https://audience.example.test', $claims[Claims::AUDIENCE->value]);
        }
    }

    /**
     * A token of either type with another issuer is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsTokenWithMismatchedIssuer(): void
    {
        $issuer   = $this->makeServiceWith(self::ISSUER_A);
        $verifier = $this->makeServiceWith(self::ISSUER_B);

        self::assertNull($verifier->parse($this->accessToken($issuer), TokenType::ACCESS));
        self::assertNull($verifier->parse($issuer->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')->reveal(), TokenType::REFRESH));
    }

    /**
     * A token of either type with another audience is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsTokenWithMismatchedAudience(): void
    {
        $issuer   = $this->makeServiceWith(self::ISSUER, 'https://audience-a.example.test');
        $verifier = $this->makeServiceWith(self::ISSUER, 'https://audience-b.example.test');

        self::assertNull($verifier->parse($this->accessToken($issuer), TokenType::ACCESS));
        self::assertNull($verifier->parse($issuer->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')->reveal(), TokenType::REFRESH));
    }

    /**
     * A token at most `leewaySeconds` past its `exp` still parses.
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
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(1, self::REFRESH_TTL_MINUTES, 60 * 24 * 180, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );

        $token = $service->issueAccessToken($identity, $principal, null, null)->reveal();

        // Advance past exp but within the 30-second leeway window.
        $advanced = $this->now->copy()->addSeconds(65);
        Carbon::setTestNow($advanced);
        JWT::$timestamp = $advanced->getTimestamp();

        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
    }

    /**
     * `parse()` restores the `JWT::$leeway` the consumer had set before the
     * call.
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
                $this->makeKeyring(),
                self::GUARD,
                new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
                15,
                self::ISSUER,
                self::AUDIENCE,
            );

            $token  = $service->issueAccessToken($identity, $principal, null, null)->reveal();
            $claims = $service->parse($token, TokenType::ACCESS);

            self::assertIsArray($claims);
            self::assertSame(99, JWT::$leeway);
        } finally {
            JWT::$leeway = 0;
        }
    }

    /**
     * A parse failure is debug-logged with the exception class.
     *
     * @return void
     */
    public function testParseDebugLogsFailureWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT decode failed', \Mockery::on(static fn (mixed $context): bool => is_array($context) && isset($context['exception'], $context['reason'])));

        self::assertNull($this->makeServiceWith(logger: $logger)->parse('not-a-jwt'));
    }

    /**
     * An issuer mismatch is debug-logged with the expected and received issuer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseDebugLogsIssuerMismatchWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with(
                'JWT issuer mismatch',
                \Mockery::on(static fn (mixed $context): bool => is_array($context)
                    && ($context['expected'] ?? null) === self::ISSUER_B
                    && ($context['received'] ?? null) === self::ISSUER_A),
            );

        self::assertNull($this->makeServiceWith(self::ISSUER_B, logger: $logger)->parse($this->accessToken($this->makeServiceWith(self::ISSUER_A))));
    }

    /**
     * An audience mismatch is debug-logged with the expected and received
     * audience.
     *
     * @return void
     */
    public function testParseDebugLogsAudienceMismatchWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT audience mismatch', ['expected' => self::AUDIENCE, 'received' => [self::AUDIENCE]]);

        $claims = [
            Claims::ISSUER->value       => self::ISSUER,
            Claims::AUDIENCE->value     => [self::AUDIENCE],
            Claims::CLIENT_ID->value    => self::GUARD,
            Claims::SUBJECT->value      => 'identity-7',
            Claims::SUBJECT_TYPE->value => 'person',
            Claims::PRINCIPAL->value    => 'principal-3',
            Claims::JWT_ID->value       => 'token-id',
            Claims::ISSUED_AT->value    => $this->now->getTimestamp(),
            Claims::EXPIRES_AT->value   => $this->now->getTimestamp() + 600,
        ];

        $token = JWT::encode($claims, self::SECRET, self::ALGORITHM, self::KID, ['typ' => TokenType::ACCESS->value]);

        self::assertNull($this->makeServiceWith(logger: $logger)->parse($token, TokenType::ACCESS));
    }

    /**
     * Build a service with the test keyring and the issuer, audience and logger
     * given.
     *
     * @param  string  $issuer
     * @param  string  $audience
     * @param  ?\Psr\Log\LoggerInterface  $logger
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \InvalidArgumentException
     */
    private function makeServiceWith(string $issuer = self::ISSUER, string $audience = self::AUDIENCE, ?LoggerInterface $logger = null): JwtTokenService
    {
        return new JwtTokenService(
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            $issuer,
            $audience,
            $logger,
        );
    }

    /**
     * An access token the service issues for mock context objects, with no
     * session.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function accessToken(JwtTokenService $service): string
    {
        return $service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null)->reveal();
    }
}
