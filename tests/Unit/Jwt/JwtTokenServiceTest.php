<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use Tests\Unit\Stubs\StubUncastDevice;

/**
 * Claim-policy unit tests for `JwtTokenService`: the `grd` claim that binds
 * every token to its issuing guard, and the claims each token type must carry.
 *
 * Every service here shares one keyring, so a token from another guard is
 * signed with a key the verifier holds and only the guard claim rejects it.
 * Both token types require `exp`, `iat`, `jti`, `typ`, and `grd`; access tokens
 * also require `sub` and `pid`, and refresh tokens `did`. Each required-claim
 * row starts from a correctly signed token that parses, then removes or blanks
 * one claim, so a rejection can only come from that claim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceTest extends JwtTokenServiceTestCase
{
    /** @var string A second guard sharing the test keyring. */
    private const string OTHER_GUARD = 'admin';

    /**
     * A complete token of each type parses, so the rejections below come only
     * from the claim each row removes.
     *
     * @return void
     */
    public function testCompleteTokensParse(): void
    {
        self::assertIsArray($this->makeService()->parse($this->encode($this->completeClaims(TokenType::ACCESS)), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($this->completeClaims(TokenType::REFRESH)), TokenType::REFRESH));
    }

    /**
     * Rows of `[type, claim]` for every claim each type requires.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType, 1: \SineMacula\Laravel\Authentication\Jwt\Enums\Claims}>
     */
    public static function provideRequiredClaims(): iterable
    {
        foreach (TokenType::cases() as $type) {
            foreach ($type->requiredClaims() as $claim) {
                yield "{$type->value} {$claim->value}" => [$type, $claim];
            }
        }
    }

    /**
     * A token missing a claim its type requires is rejected, with or without an
     * expected type.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\Claims  $claim
     * @return void
     */
    #[DataProvider('provideRequiredClaims')]
    public function testParseRejectsATokenMissingARequiredClaim(TokenType $type, Claims $claim): void
    {
        $claims = $this->completeClaims($type);

        unset($claims[$claim->value]);

        $token = $this->encode($claims);

        self::assertNull($this->makeService()->parse($token, $type));
        self::assertNull($this->makeService()->parse($token));
    }

    /**
     * A required claim present with a `null` value counts as missing.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\Claims  $claim
     * @return void
     */
    #[DataProvider('provideRequiredClaims')]
    public function testParseRejectsARequiredClaimThatIsNull(TokenType $type, Claims $claim): void
    {
        $claims = $this->completeClaims($type);

        $claims[$claim->value] = null;

        self::assertNull($this->makeService()->parse($this->encode($claims), $type));
    }

    /**
     * Rows of `[type, claim]` for the required string claims that can be sent
     * empty.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType, 1: \SineMacula\Laravel\Authentication\Jwt\Enums\Claims}>
     */
    public static function provideRequiredStringClaims(): iterable
    {
        yield from [
            'access jti'  => [TokenType::ACCESS, Claims::JWT_ID],
            'access sub'  => [TokenType::ACCESS, Claims::SUBJECT],
            'access pid'  => [TokenType::ACCESS, Claims::PRINCIPAL_ID],
            'refresh jti' => [TokenType::REFRESH, Claims::JWT_ID],
            'refresh did' => [TokenType::REFRESH, Claims::DEVICE_ID],
        ];
    }

    /**
     * A required string claim sent as an empty string counts as missing.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\Claims  $claim
     * @return void
     */
    #[DataProvider('provideRequiredStringClaims')]
    public function testParseRejectsARequiredClaimThatIsEmpty(TokenType $type, Claims $claim): void
    {
        $claims = $this->completeClaims($type);

        $claims[$claim->value] = '';

        self::assertNull($this->makeService()->parse($this->encode($claims), $type));
    }

    /**
     * `did` stays optional on access tokens (access-only mode), whether absent
     * or `null`, and `pid` stays optional on refresh tokens.
     *
     * @return void
     */
    public function testParseAcceptsTheOptionalClaimsBeingAbsent(): void
    {
        $access = $this->completeClaims(TokenType::ACCESS);

        unset($access[Claims::DEVICE_ID->value]);

        $nullDevice                           = $this->completeClaims(TokenType::ACCESS);
        $nullDevice[Claims::DEVICE_ID->value] = null;

        $refresh = $this->completeClaims(TokenType::REFRESH);

        unset($refresh[Claims::PRINCIPAL_ID->value]);

        self::assertIsArray($this->makeService()->parse($this->encode($access), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($nullDevice), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($refresh), TokenType::REFRESH));
    }

    /**
     * Without an expected type, the token's own `typ` selects the required
     * claims: a refresh token without `did` is rejected even though an access
     * token needs no `did`.
     *
     * @return void
     */
    public function testParseWithoutExpectedTypeAppliesTheTokensOwnType(): void
    {
        $claims = $this->completeClaims(TokenType::REFRESH);

        unset($claims[Claims::DEVICE_ID->value]);

        self::assertNull($this->makeService()->parse($this->encode($claims)));
    }

    /**
     * Without an expected type, a token whose `typ` is not a known type is
     * rejected and the unknown value is debug-logged.
     *
     * @return void
     */
    public function testParseRejectsAnUnknownTypeAndLogsIt(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT typ unknown', ['received' => 'id']);

        $claims                      = $this->completeClaims(TokenType::ACCESS);
        $claims[Claims::TYPE->value] = 'id';

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims)));
    }

    /**
     * A missing required claim is debug-logged with the claim and the type.
     *
     * @return void
     */
    public function testParseLogsTheMissingClaim(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT required claim missing', ['claim' => 'pid', 'typ' => 'access']);

        $claims = $this->completeClaims(TokenType::ACCESS);

        unset($claims[Claims::PRINCIPAL_ID->value]);

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
    }

    /**
     * A guard, issuer, audience, or `typ` mismatch is reported before a missing
     * claim, so a token from another guard is logged as such even when it also
     * lacks a claim this guard's tokens require.
     *
     * @return void
     */
    public function testParseReportsAClaimMismatchBeforeAMissingClaim(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT guard mismatch', ['expected' => self::GUARD, 'received' => self::OTHER_GUARD]);

        $claims                       = $this->completeClaims(TokenType::ACCESS);
        $claims[Claims::GUARD->value] = self::OTHER_GUARD;

        unset($claims[Claims::PRINCIPAL_ID->value]);

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
    }

    /**
     * Access and refresh tokens both carry the issuing guard's name.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuedTokensCarryTheIssuingGuard(): void
    {
        $service = $this->makeService();

        $access  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null), TokenType::ACCESS);
        $refresh = $service->parse($service->issueRefreshToken($this->mockDevice('device-42'), 'rotation-id'), TokenType::REFRESH);

        self::assertIsArray($access);
        self::assertIsArray($refresh);
        self::assertSame(self::GUARD, $access[Claims::GUARD->value]);
        self::assertSame(self::GUARD, $refresh[Claims::GUARD->value]);
    }

    /**
     * An access token issued for another guard with the same key is rejected,
     * whether or not a token type is expected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsAnAccessTokenIssuedForAnotherGuard(): void
    {
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null);

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($token));
        self::assertIsArray($this->makeServiceFor(self::OTHER_GUARD)->parse($token, TokenType::ACCESS));
    }

    /**
     * A refresh token issued for another guard with the same key is rejected.
     *
     * @return void
     */
    public function testParseRejectsARefreshTokenIssuedForAnotherGuard(): void
    {
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueRefreshToken($this->mockDevice('device-42'), 'rotation-id');

        self::assertNull($this->makeService()->parse($token, TokenType::REFRESH));
    }

    /**
     * A correctly signed token with every other claim but no `grd` is rejected.
     *
     * @return void
     */
    public function testParseRejectsATokenWithoutAGuardClaim(): void
    {
        $token = JWT::encode(
            [
                Claims::SUBJECT->value      => 'identity-7',
                Claims::PRINCIPAL_ID->value => 'principal-3',
                Claims::JWT_ID->value       => 'access-token-id',
                Claims::ISSUED_AT->value    => $this->now->getTimestamp(),
                Claims::EXPIRES_AT->value   => $this->now->getTimestamp() + 600,
                Claims::TYPE->value         => TokenType::ACCESS->value,
            ],
            self::SECRET,
            self::ALGORITHM,
            self::KID,
        );

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
    }

    /**
     * A guard mismatch is debug-logged with the expected and received guard.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseDebugLogsAGuardMismatchWhenLoggerSupplied(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT guard mismatch', ['expected' => self::GUARD, 'received' => self::OTHER_GUARD]);

        $verifier = new JwtTokenService(
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES),
            30,
            null,
            null,
            $logger,
        );

        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null);

        self::assertNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A service cannot be built without a guard to bind its tokens to.
     *
     * @return void
     */
    public function testConstructorRejectsAnEmptyGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('JWT token service requires a non-empty guard name.');

        $this->makeServiceFor('');
    }

    /**
     * The service exposes the lifetimes it issues with, for code that stamps a
     * new device's deadlines.
     *
     * @return void
     */
    public function testExposesItsLifetimes(): void
    {
        $lifetimes = new TokenLifetimes(7, 70, 700);

        $service = new JwtTokenService($this->makeKeyring(), self::GUARD, $lifetimes, 30);

        self::assertSame($lifetimes, $service->lifetimes());
    }

    /**
     * A refresh token expires at the device's stored idle deadline, not the
     * idle lifetime from now: the row decides how long the session lasts.
     *
     * @return void
     */
    public function testRefreshTokenExpiresAtTheDevicesIdleDeadline(): void
    {
        $device = $this->mockDeviceEndingAt('device-42', $this->now->copy()->addHours(2), $this->now->copy()->addDays(10));

        $claims = $this->refreshClaims($this->makeService()->issueRefreshToken($device, 'rotation-id'));

        self::assertSame($this->now->getTimestamp() + 7200, $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * A refresh token never expires after the device's absolute deadline, even
     * when the stored idle deadline lies beyond it.
     *
     * @return void
     */
    public function testRefreshTokenNeverExpiresAfterTheAbsoluteDeadline(): void
    {
        $device = $this->mockDeviceEndingAt('device-42', $this->now->copy()->addDays(10), $this->now->copy()->addDay());

        $claims = $this->refreshClaims($this->makeService()->issueRefreshToken($device, 'rotation-id'));

        self::assertSame($this->now->getTimestamp() + 86400, $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * An access token expires after the access lifetime when there is no
     * device, or when the device's session outlasts the token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokenExpiresAfterTheAccessLifetimeWithinItsSession(): void
    {
        $expected = $this->now->getTimestamp() + (self::ACCESS_TTL_MINUTES * 60);

        self::assertSame($expected, $this->accessExpiry(null));
        self::assertSame($expected, $this->accessExpiry($this->mockDeviceEndingAt('device-42', $this->now->copy()->addDay(), $this->now->copy()->addDay())));
    }

    /**
     * An access token never expires after the absolute deadline of its device's
     * session, even when the idle deadline lies beyond it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokenExpiresAtTheAbsoluteDeadlineWhenItComesFirst(): void
    {
        foreach ([120, 1] as $absoluteIn) {

            $device = $this->mockDeviceEndingAt('device-42', $this->now->copy()->addDay(), $this->now->copy()->addSeconds($absoluteIn));

            self::assertSame($this->now->getTimestamp() + $absoluteIn, $this->accessExpiry($device));
        }
    }

    /**
     * A caller that judged the device at a given time issues at that time:
     * `iat` and the access lifetime count from it, cut to the whole second.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesAtTheGivenTime(): void
    {
        $issuedAt = CarbonImmutable::instance($this->now)->subSeconds(10)->addMilliseconds(900);
        $service  = $this->makeService();
        $device   = $this->mockDevice('device-42');

        $access  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), $device, $issuedAt), TokenType::ACCESS);
        $refresh = $this->refreshClaims($service->issueRefreshToken($device, 'rotation-id', null, $issuedAt));

        self::assertIsArray($access);
        self::assertSame($this->now->getTimestamp() - 10, $access[Claims::ISSUED_AT->value]);
        self::assertSame($this->now->getTimestamp() - 10 + (self::ACCESS_TTL_MINUTES * 60), $access[Claims::EXPIRES_AT->value]);
        self::assertSame($this->now->getTimestamp() - 10, $refresh[Claims::ISSUED_AT->value]);
    }

    /**
     * Rows of `[seconds from now to the idle deadline or null, seconds from
     * now to the absolute deadline or null]` for sessions that have ended.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield from [
            'idle reached this second'     => [0, 86400],
            'idle passed'                  => [-60, 86400],
            'absolute reached this second' => [3600, 0],
            'absolute passed'              => [3600, -60],
            'no idle deadline'             => [null, 86400],
            'no absolute deadline'         => [3600, null],
        ];
    }

    /**
     * No access token is issued for a device whose session has ended or has no
     * deadlines: it could never be used, and a token must not outlive its
     * session.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideEndedSessions')]
    public function testRefusesAnAccessTokenForAnEndedSession(?int $idleIn, ?int $absoluteIn): void
    {
        $device = $this->mockDeviceEndingAt('device-42', $this->secondsFromNow($idleIn), $this->secondsFromNow($absoluteIn));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), $device);
    }

    /**
     * No refresh token is issued for a device whose session has ended or has no
     * deadlines, so issuing cannot extend a session that is over.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @return void
     */
    #[DataProvider('provideEndedSessions')]
    public function testRefusesARefreshTokenForAnEndedSession(?int $idleIn, ?int $absoluteIn): void
    {
        $device = $this->mockDeviceEndingAt('device-42', $this->secondsFromNow($idleIn), $this->secondsFromNow($absoluteIn));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        $this->makeService()->issueRefreshToken($device, 'rotation-id');
    }

    /**
     * A device loaded without its deadline columns cannot be issued for: the
     * missing deadline is reported rather than read as "no session" or as a
     * live one.
     *
     * @return void
     */
    public function testReportsADeviceLoadedWithoutItsDeadlines(): void
    {
        $device = new StubUncastDevice;
        $device->setRawAttributes(['id' => 'device-42']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `idle_expires_at` attribute is not loaded');

        $this->makeService()->issueRefreshToken($device, 'rotation-id');
    }

    /**
     * Build a service on the shared test keyring bound to the named guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeServiceFor(string $guard): JwtTokenService
    {
        return new JwtTokenService(
            $this->makeKeyring(),
            $guard,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES),
            30,
        );
    }

    /**
     * Build a complete, valid claim set for the token type.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     */
    private function completeClaims(TokenType $type): array
    {
        $claims = [
            Claims::ISSUED_AT->value    => $this->now->getTimestamp(),
            Claims::EXPIRES_AT->value   => $this->now->getTimestamp() + 600,
            Claims::JWT_ID->value       => 'token-id',
            Claims::TYPE->value         => $type->value,
            Claims::GUARD->value        => self::GUARD,
            Claims::PRINCIPAL_ID->value => 'principal-3',
            Claims::DEVICE_ID->value    => 'device-42',
        ];

        if ($type === TokenType::ACCESS) {
            $claims[Claims::SUBJECT->value] = 'identity-7';
        }

        return $claims;
    }

    /**
     * Sign the claims with the shared test key.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encode(array $claims): string
    {
        return JWT::encode($claims, self::SECRET, self::ALGORITHM, self::KID);
    }

    /**
     * Build a service with the test defaults and the supplied logger.
     *
     * @param  \Psr\Log\LoggerInterface  $logger
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeServiceWithLogger(LoggerInterface $logger): JwtTokenService
    {
        return new JwtTokenService(
            $this->makeKeyring(),
            self::GUARD,
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES),
            30,
            null,
            null,
            $logger,
        );
    }

    /**
     * Decode a refresh token issued by the default service.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private function refreshClaims(string $token): array
    {
        $claims = $this->makeService()->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * The time the given number of seconds from now, or `null`.
     *
     * @param  ?int  $seconds
     * @return ?\Carbon\CarbonImmutable
     */
    private function secondsFromNow(?int $seconds): ?CarbonImmutable
    {
        return $seconds === null ? null : CarbonImmutable::instance($this->now)->addSeconds($seconds);
    }

    /**
     * The `exp` claim of an access token the default service issues for the
     * device.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return mixed
     *
     * @throws \Random\RandomException
     */
    private function accessExpiry(?Device $device): mixed
    {
        $service = $this->makeService();
        $claims  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), $device), TokenType::ACCESS);

        self::assertIsArray($claims);

        return $claims[Claims::EXPIRES_AT->value];
    }
}
