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
 * Parse-side unit tests for `JwtTokenService` - `parse()` and the issuer /
 * audience / header `typ` / leeway / logger surface.
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
        $verifier = new JwtTokenService(
            $this->makeKeyring('a-completely-different-secret-key-with-32!'),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );

        $token = $issuer->issueAccessToken($identity, $principal, null, null);

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
        $token   = $service->issueAccessToken($identity, $principal, null, null);

        $this->advanceClock(self::ACCESS_TTL_MINUTES + 1);

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * A refresh token presented to `parse()` with `expectedType = access` is
     * rejected - the header `typ` check prevents token-type confusion.
     *
     * @return void
     */
    public function testParseRejectsRefreshTokenWhenAccessTypeIsExpected(): void
    {
        $session = $this->mockSession('session-42');

        $service = $this->makeService();
        $token   = $service->issueRefreshToken($session, 'rotation-id');

        self::assertNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * An access token presented to `parse()` with `expectedType = refresh` is
     * rejected - the header `typ` check prevents token-type confusion.
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
        $token   = $service->issueAccessToken($identity, $principal, null, null);

        self::assertNull($service->parse($token, TokenType::REFRESH));
    }

    /**
     * Every token carries the service's issuer and audience, and parses cleanly
     * on that service.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseAcceptsIssuerAndAudienceOnMatchingService(): void
    {
        $service = $this->makeServiceWith(self::ISSUER_A, 'https://audience.example.test');

        foreach ([$this->accessToken($service), $service->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')] as $token) {

            $claims = $service->parse($token);

            self::assertIsArray($claims);
            self::assertSame(self::ISSUER_A, $claims[Claims::ISSUER->value]);
            self::assertSame('https://audience.example.test', $claims[Claims::AUDIENCE->value]);
        }
    }

    /**
     * A token whose issuer claim does not match the verifier's issuer is
     * rejected, of either type.
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
        self::assertNull($verifier->parse($issuer->issueRefreshToken($this->mockSession('session-42'), 'rotation-id'), TokenType::REFRESH));
    }

    /**
     * A token whose audience claim does not match the verifier's audience is
     * rejected, of either type.
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
        self::assertNull($verifier->parse($issuer->issueRefreshToken($this->mockSession('session-42'), 'rotation-id'), TokenType::REFRESH));
    }

    /**
     * A service cannot be built without an issuer or an audience to write into
     * every token and check on every parse.
     *
     * @return void
     */
    public function testConstructorRejectsAnEmptyIssuerOrAudience(): void
    {
        foreach ([['', self::AUDIENCE], [self::ISSUER, '']] as [$issuer, $audience]) {
            try {
                $this->makeServiceWith($issuer, $audience);

                self::fail('Expected the service to need an issuer and an audience.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('JWT token service requires a non-empty issuer and audience.', $exception->getMessage());
            }
        }
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
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(1, self::REFRESH_TTL_MINUTES, 60 * 24 * 180, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );

        $token = $service->issueAccessToken($identity, $principal, null, null);

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
                $this->makeKeyring(),
                self::GUARD,
                new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
                15,
                self::ISSUER,
                self::AUDIENCE,
            );

            $token  = $service->issueAccessToken($identity, $principal, null, null);
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

        self::assertNull($this->makeServiceWith(logger: $logger)->parse('not-a-jwt'));
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
     * Audience-mismatch failures are debug-logged with the expected vs received
     * audience, an array audience included.
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
     * Build a service with the test keyring and lifetimes and the supplied
     * issuer, audience and logger.
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
     * An access token the service issues for mock identity and principal
     * context objects, with no session.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function accessToken(JwtTokenService $service): string
    {
        return $service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null);
    }
}
