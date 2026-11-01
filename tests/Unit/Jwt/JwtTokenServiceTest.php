<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Claim-policy unit tests for `JwtTokenService`: the header `typ` that tells
 * the token types apart, the `client_id` claim that binds every token to its
 * issuing guard, the claims each token type must carry, and the access token's
 * shape.
 *
 * Every service here shares one keyring, so a token from another guard is
 * signed with a key the verifier holds and only the guard claim rejects it.
 * Both token types require `iss`, `aud`, `client_id`, `jti`, `iat` and `exp`;
 * access tokens also require `sub`, `sub_type` and `principal`, and refresh
 * tokens `sid`. Each required-claim row starts from a correctly signed token
 * that parses, then removes or blanks one claim, so a rejection can only come
 * from that claim.
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

    /** @var string The API key id a client credentials token names. */
    private const string KEY_ID = '0196a1d2-7c3e-7b8a-9f10-2a3b4c5d6e7f';

    /**
     * A complete token of each type parses, so the rejections below come only
     * from the claim each row removes.
     *
     * @return void
     */
    public function testCompleteTokensParse(): void
    {
        self::assertIsArray($this->makeService()->parse($this->encode($this->completeClaims(TokenType::ACCESS)), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($this->completeClaims(TokenType::REFRESH), TokenType::REFRESH), TokenType::REFRESH));
    }

    /**
     * Parsed claims are keyed by name, so a claim whose name is numeric, which
     * decodes to an integer key, is left out of them.
     *
     * @return void
     */
    public function testAClaimWithANumericNameIsLeftOut(): void
    {
        $claims = $this->completeClaims(TokenType::ACCESS);
        $token  = JWT::encode([...$claims, 7 => 'numeric'], self::SECRET, self::ALGORITHM, self::KID, ['typ' => TokenType::ACCESS->value]);

        self::assertSame($claims, $this->makeService()->parse($token, TokenType::ACCESS));
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

        $token = $this->encode($claims, $type);

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

        self::assertNull($this->makeService()->parse($this->encode($claims, $type), $type));
    }

    /**
     * Rows of `[type, claim]` for the required string claims that can be sent
     * empty.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType, 1: \SineMacula\Laravel\Authentication\Jwt\Enums\Claims}>
     */
    public static function provideRequiredStringClaims(): iterable
    {
        foreach ([Claims::ISSUER, Claims::AUDIENCE, Claims::CLIENT_ID, Claims::JWT_ID] as $claim) {
            yield "access {$claim->value}" => [TokenType::ACCESS, $claim];
            yield "refresh {$claim->value}" => [TokenType::REFRESH, $claim];
        }

        yield from [
            'access sub'       => [TokenType::ACCESS, Claims::SUBJECT],
            'access sub_type'  => [TokenType::ACCESS, Claims::SUBJECT_TYPE],
            'access principal' => [TokenType::ACCESS, Claims::PRINCIPAL],
            'refresh sid'      => [TokenType::REFRESH, Claims::SESSION_ID],
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

        self::assertNull($this->makeService()->parse($this->encode($claims, $type), $type));
    }

    /**
     * `sid` stays optional on access tokens (access-only mode), whether absent
     * or `null`, so long as the token then carries no `auth_time` or `amr`;
     * and `principal` stays optional on refresh tokens.
     *
     * @return void
     */
    public function testParseAcceptsTheOptionalClaimsBeingAbsent(): void
    {
        $access = $this->sessionless($this->completeClaims(TokenType::ACCESS));

        $nullSession                            = $access;
        $nullSession[Claims::SESSION_ID->value] = null;

        $refresh = $this->completeClaims(TokenType::REFRESH);

        unset($refresh[Claims::PRINCIPAL->value]);

        self::assertIsArray($this->makeService()->parse($this->encode($access), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($nullSession), TokenType::ACCESS));
        self::assertIsArray($this->makeService()->parse($this->encode($refresh, TokenType::REFRESH), TokenType::REFRESH));
    }

    /**
     * Without an expected type, the token's own header type selects the
     * required claims: a refresh token without `sid` is rejected even though an
     * access token needs no `sid`.
     *
     * @return void
     */
    public function testParseWithoutExpectedTypeAppliesTheTokensOwnType(): void
    {
        $claims = $this->completeClaims(TokenType::REFRESH);

        unset($claims[Claims::SESSION_ID->value]);

        self::assertNull($this->makeService()->parse($this->encode($claims, TokenType::REFRESH)));
    }

    /**
     * Rows of `[header typ, the type it names or null]`: the two types, in any
     * case and with or without the `application/` media type prefix, and the
     * values that name neither.
     *
     * @return iterable<string, array{0: mixed, 1: ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType}>
     */
    public static function provideHeaderTypes(): iterable
    {
        yield from [
            'access'                       => ['at+jwt', TokenType::ACCESS],
            'access upper case'            => ['AT+JWT', TokenType::ACCESS],
            'access media type'            => ['application/at+jwt', TokenType::ACCESS],
            'access mixed-case media type' => ['Application/At+Jwt', TokenType::ACCESS],
            'refresh'                      => ['refresh+jwt', TokenType::REFRESH],
            'refresh media type'           => ['application/refresh+jwt', TokenType::REFRESH],
            'php-jwt default'              => ['JWT', null],
            'old access claim value'       => ['access', null],
            'old refresh claim value'      => ['refresh', null],
            'empty'                        => ['', null],
            'prefix only'                  => ['application/', null],
            'padded'                       => [' at+jwt', null],
            'other media type'             => ['text/at+jwt', null],
            'doubled prefix'               => ['application/application/at+jwt', null],
            'number'                       => [1, null],
            'null'                         => [null, null],
        ];
    }

    /**
     * A token parses only when its header type names its type: with an expected
     * type it must name that type, and without one it may name either, whose
     * own claims are then required. An access token's claims hold every claim a
     * refresh token requires, so under a refresh header they parse as one: the
     * header, not the claims, names the type. A header type that names neither
     * is rejected, whatever the claims.
     *
     * @param  mixed  $typ
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $named
     * @return void
     */
    #[DataProvider('provideHeaderTypes')]
    public function testParseHoldsTheTokenToItsHeaderType(mixed $typ, ?TokenType $named): void
    {
        $service = $this->makeService();

        foreach (TokenType::cases() as $type) {

            $token  = $this->sign(['alg' => self::ALGORITHM, 'kid' => self::KID, 'typ' => $typ], $this->completeClaims($type));
            $parses = $named === $type || ($named === TokenType::REFRESH && $type === TokenType::ACCESS);

            foreach (TokenType::cases() as $expected) {
                self::assertSame($parses && $expected === $named, is_array($service->parse($token, $expected)), "{$type->name} claims expected as {$expected->name}");
            }

            self::assertSame($parses, is_array($service->parse($token)), "{$type->name} claims without an expected type");
        }
    }

    /**
     * A correctly signed token whose header has no `typ` at all is rejected:
     * the profile has no default type.
     *
     * @return void
     */
    public function testParseRejectsATokenWithoutAHeaderType(): void
    {
        $token = $this->sign(['alg' => self::ALGORITHM, 'kid' => self::KID], $this->completeClaims(TokenType::ACCESS));

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($token));
    }

    /**
     * A token whose header type is not the one expected is rejected, and the
     * expected and received types are debug-logged, an unknown one included.
     *
     * @return void
     */
    public function testParseLogsAHeaderTypeMismatch(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT typ header mismatch', ['expected' => 'at+jwt', 'received' => 'refresh+jwt']);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT typ header mismatch', ['expected' => null, 'received' => 'JWT']);

        $service = $this->makeServiceWithLogger($logger);

        self::assertNull($service->parse($this->encode($this->completeClaims(TokenType::ACCESS), TokenType::REFRESH), TokenType::ACCESS));
        self::assertNull($service->parse(JWT::encode($this->completeClaims(TokenType::ACCESS), self::SECRET, self::ALGORITHM, self::KID)));
    }

    /**
     * A header type mismatch with no type expected is rejected without raising
     * a PHP warning: inside a Laravel application a warning becomes an
     * exception, which would turn a rejected token into an error.
     *
     * @return void
     */
    public function testParseWithNoExpectedTypeRejectsAHeaderTypeMismatchQuietly(): void
    {
        $service = $this->makeService();
        $token   = JWT::encode($this->completeClaims(TokenType::ACCESS), self::SECRET, self::ALGORITHM, self::KID);

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });

        try {
            self::assertNull($service->parse($token));
        } finally {
            restore_error_handler();
        }
    }

    /**
     * A token that lacks a claim its type requires is reported as missing it,
     * before the profile's shape is judged, so a token without `sub_type` is
     * logged as missing the claim rather than as a subject type mismatch.
     *
     * @return void
     */
    public function testParseReportsAMissingClaimBeforeAMisshapenOne(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT required claim missing', ['claim' => 'sub_type', 'typ' => 'at+jwt']);

        $claims = $this->completeClaims(TokenType::ACCESS);

        unset($claims[Claims::SUBJECT_TYPE->value]);

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
    }

    /**
     * A token in the profile the package used before (a `typ` claim, `pid`,
     * `did` and `grd`, and php-jwt's default header type) is rejected: no
     * compatibility path exists.
     *
     * @return void
     */
    public function testParseRejectsATokenInTheOldProfile(): void
    {
        $old = [
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'identity-7',
            'pid' => 'principal-3',
            'did' => 'session-42',
            'grd' => self::GUARD,
            'typ' => 'access',
            'jti' => 'token-id',
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ];

        self::assertNull($this->makeService()->parse(JWT::encode($old, self::SECRET, self::ALGORITHM, self::KID), TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($this->encode($old), TokenType::ACCESS));
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
            ->with('JWT required claim missing', ['claim' => 'principal', 'typ' => 'at+jwt']);

        $claims = $this->completeClaims(TokenType::ACCESS);

        unset($claims[Claims::PRINCIPAL->value]);

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
    }

    /**
     * A guard, issuer or audience mismatch is reported before a missing claim,
     * so a token from another guard is logged as such even when it also lacks a
     * claim this guard's tokens require.
     *
     * @return void
     */
    public function testParseReportsAClaimMismatchBeforeAMissingClaim(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT client_id mismatch', ['expected' => self::GUARD, 'received' => self::OTHER_GUARD]);

        $claims                           = $this->completeClaims(TokenType::ACCESS);
        $claims[Claims::CLIENT_ID->value] = self::OTHER_GUARD;

        unset($claims[Claims::PRINCIPAL->value]);

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
    }

    /**
     * Rows of `[claim, value]` for a guard, issuer or audience that is not the
     * service's: another string, one that differs only in case, and an array
     * holding the service's own value.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\Claims, 1: mixed}>
     */
    public static function provideForeignBindings(): iterable
    {
        foreach (['client_id' => self::GUARD, 'iss' => self::ISSUER, 'aud' => self::AUDIENCE] as $name => $own) {

            $claim = Claims::from($name);

            yield "{$name} another" => [$claim, 'another'];
            yield "{$name} other case" => [$claim, strtoupper($own)];
            yield "{$name} array" => [$claim, [$own]];
        }
    }

    /**
     * A token of either type whose guard, issuer or audience is not the
     * service's is rejected, an array audience holding the service's own
     * included.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\Claims  $claim
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideForeignBindings')]
    public function testParseRejectsAForeignBinding(Claims $claim, mixed $value): void
    {
        foreach (TokenType::cases() as $type) {

            $claims                = $this->completeClaims($type);
            $claims[$claim->value] = $value;

            self::assertNull($this->makeService()->parse($this->encode($claims, $type), $type));
        }
    }

    /**
     * Access and refresh tokens both carry the issuing guard's name in
     * `client_id`, and the service's issuer and audience.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuedTokensCarryTheIssuingGuard(): void
    {
        $service = $this->makeServiceFor(self::OTHER_GUARD);

        $access  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null), TokenType::ACCESS);
        $refresh = $service->parse($service->issueRefreshToken($this->mockSession('session-42'), 'rotation-id'), TokenType::REFRESH);

        self::assertIsArray($access);
        self::assertIsArray($refresh);

        foreach ([$access, $refresh] as $claims) {
            self::assertSame(self::OTHER_GUARD, $claims[Claims::CLIENT_ID->value]);
            self::assertSame(self::ISSUER, $claims[Claims::ISSUER->value]);
            self::assertSame(self::AUDIENCE, $claims[Claims::AUDIENCE->value]);
        }
    }

    /**
     * Issuing never reads the principal's tenant: the token needs only the
     * principal's identifier, and the tenant comes from the caller.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuingNeverReadsThePrincipalsTenant(): void
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('principal-3');
        $principal->shouldNotReceive('getTenant');

        $claims = $this->makeService()->parse($this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $principal, null, null), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL->value]);
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
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null);

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
        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueRefreshToken($this->mockSession('session-42'), 'rotation-id');

        self::assertNull($this->makeService()->parse($token, TokenType::REFRESH));
    }

    /**
     * A correctly signed token with every other claim but no `client_id` is
     * rejected.
     *
     * @return void
     */
    public function testParseRejectsATokenWithoutAGuardClaim(): void
    {
        $claims = $this->completeClaims(TokenType::ACCESS);

        unset($claims[Claims::CLIENT_ID->value]);

        self::assertNull($this->makeService()->parse($this->encode($claims), TokenType::ACCESS));
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
            ->with('JWT client_id mismatch', ['expected' => self::GUARD, 'received' => self::OTHER_GUARD]);

        $verifier = $this->makeServiceWithLogger($logger);

        $token = $this->makeServiceFor(self::OTHER_GUARD)->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null);

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
     * A service cannot be built without an issuer or an audience to write into
     * every token and check on every parse: either one empty is refused.
     *
     * @return void
     */
    public function testConstructorRejectsAnEmptyIssuerOrAudience(): void
    {
        foreach ([['', self::AUDIENCE], [self::ISSUER, '']] as [$issuer, $audience]) {
            try {
                new JwtTokenService($this->makeKeyring(), self::GUARD, new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30), 30, $issuer, $audience);

                self::fail('Expected the service to need an issuer and an audience.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('JWT token service requires a non-empty issuer and audience.', $exception->getMessage());
            }
        }
    }

    /**
     * A refresh token offered as proof of a session is accepted after it has
     * expired, with the same claims `parse()` returns for a live one, while
     * `parse()` itself rejects it.
     *
     * @return void
     */
    public function testParseRefreshProofAcceptsAnExpiredRefreshToken(): void
    {
        $service = $this->makeService();
        $record  = $this->mockSessionEndingAt('session-42', $this->now->copy()->addMinutes(10), $this->now->copy()->addMinutes(20));
        $token   = $service->issueRefreshToken($record, 'rotation-id', $this->mockPrincipal('principal-3'));
        $live    = $service->parseRefreshProof($token);

        self::assertSame($service->parse($token, TokenType::REFRESH), $live);

        $this->advanceClock(60 * 24 * 365);

        self::assertNull($service->parse($token, TokenType::REFRESH));
        self::assertSame($live, $service->parseRefreshProof($token));
        self::assertSame('session-42', $live[Claims::SESSION_ID->value] ?? null);
        self::assertSame('rotation-id', $live[Claims::JWT_ID->value] ?? null);
    }

    /**
     * Every check but expiry still applies to a proof: a token that is not a
     * refresh token, that another guard issued, that is signed with another
     * key, that is issued in the future, that lacks a claim a refresh token
     * requires, or that is not a JWT at all, proves nothing; and a failure is
     * logged as `parse()` logs it. Its header and binding are checked on an
     * expired one too: an expired token with an access header, another guard's,
     * issuer's or audience's proves nothing either.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRefreshProofKeepsEveryOtherCheck(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')->atLeast()->once();

        $service = $this->makeServiceWithLogger($logger);

        $claims = $this->completeClaims(TokenType::REFRESH);

        unset($claims[Claims::SESSION_ID->value]);

        $future = $this->completeClaims(TokenType::REFRESH);

        $future[Claims::ISSUED_AT->value] = $this->now->getTimestamp() + 3600;

        $otherKey = new JwtTokenService($this->makeKeyring(str_repeat('k', 32)), self::GUARD, $service->lifetimes(), 30, self::ISSUER, self::AUDIENCE);

        self::assertNull($service->parseRefreshProof($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null)));
        self::assertNull($service->parseRefreshProof($this->makeServiceFor(self::OTHER_GUARD)->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')));
        self::assertNull($service->parseRefreshProof($otherKey->issueRefreshToken($this->mockSession('session-42'), 'rotation-id')));
        self::assertNull($service->parseRefreshProof($this->encode($future, TokenType::REFRESH)));
        self::assertNull($service->parseRefreshProof($this->encode($claims, TokenType::REFRESH)));
        self::assertNull($service->parseRefreshProof('not-a-jwt'));
        self::assertIsArray($service->parseRefreshProof($this->encode($this->completeClaims(TokenType::REFRESH), TokenType::REFRESH)));

        $expired                            = $this->completeClaims(TokenType::REFRESH);
        $expired[Claims::EXPIRES_AT->value] = $this->now->getTimestamp() - 3600;

        self::assertIsArray($service->parseRefreshProof($this->encode($expired, TokenType::REFRESH)));
        self::assertNull($service->parseRefreshProof($this->encode($expired, TokenType::ACCESS)));
        self::assertNull($service->parseRefreshProof($this->sign(['alg' => self::ALGORITHM, 'kid' => self::KID], $expired)));

        foreach ([Claims::CLIENT_ID, Claims::ISSUER, Claims::AUDIENCE] as $binding) {
            self::assertNull($service->parseRefreshProof($this->encode([...$expired, $binding->value => 'another'], TokenType::REFRESH)));
        }
    }

    /**
     * Checking a proof applies the service's leeway only while it decodes, and
     * restores the leeway set before, whether the proof is accepted or not.
     *
     * @return void
     */
    public function testParseRefreshProofRestoresThePreviousLeeway(): void
    {
        $previous = JWT::$leeway;

        JWT::$leeway = 7;

        try {
            $service = $this->makeService();

            $service->parseRefreshProof($service->issueRefreshToken($this->mockSession('session-42'), 'rotation-id'));

            self::assertSame(7, JWT::$leeway);

            $service->parseRefreshProof('not-a-jwt');

            self::assertSame(7, JWT::$leeway);
        } finally {
            JWT::$leeway = $previous;
        }
    }

    /**
     * The service exposes the lifetimes it issues with, for code that stamps a
     * new session's deadlines.
     *
     * @return void
     */
    public function testExposesItsLifetimes(): void
    {
        $lifetimes = new TokenLifetimes(7, 70, 700, 30);

        $service = new JwtTokenService($this->makeKeyring(), self::GUARD, $lifetimes, 30, self::ISSUER, self::AUDIENCE);

        self::assertSame($lifetimes, $service->lifetimes());
    }

    /**
     * A refresh token expires at the session's stored idle deadline, not the
     * idle lifetime from now: the row decides how long the session lasts.
     *
     * @return void
     */
    public function testRefreshTokenExpiresAtTheSessionsIdleDeadline(): void
    {
        $record = $this->mockSessionEndingAt('session-42', $this->now->copy()->addHours(2), $this->now->copy()->addDays(10));

        $claims = $this->refreshClaims($this->makeService()->issueRefreshToken($record, 'rotation-id'));

        self::assertSame($this->now->getTimestamp() + 7200, $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * A refresh token of a session with no absolute deadline expires at its
     * idle deadline, however far ahead.
     *
     * @return void
     */
    public function testRefreshTokenOfASessionWithoutAnAbsoluteDeadlineExpiresAtItsIdleDeadline(): void
    {
        $record = $this->mockSessionEndingAt('session-42', $this->now->copy()->addDays(400), null);

        $claims = $this->refreshClaims($this->makeService()->issueRefreshToken($record, 'rotation-id'));

        self::assertSame($this->now->getTimestamp() + (400 * 86400), $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * A refresh token never expires after the session's absolute deadline, even
     * when the stored idle deadline lies beyond it.
     *
     * @return void
     */
    public function testRefreshTokenNeverExpiresAfterTheAbsoluteDeadline(): void
    {
        $record = $this->mockSessionEndingAt('session-42', $this->now->copy()->addDays(10), $this->now->copy()->addDay());

        $claims = $this->refreshClaims($this->makeService()->issueRefreshToken($record, 'rotation-id'));

        self::assertSame($this->now->getTimestamp() + 86400, $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * A caller that judged the session at a given time issues at that time:
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
        $record   = $this->mockSession('session-42');

        $access  = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null, $issuedAt), TokenType::ACCESS);
        $refresh = $this->refreshClaims($service->issueRefreshToken($record, 'rotation-id', null, $issuedAt));

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
            'no deadlines'                 => [null, null],
            'no absolute, idle reached'    => [0, null],
        ];
    }

    /**
     * No access token is issued for a session that has ended or has no idle
     * deadline: it could never be used, and a token must not outlive its
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
        $record = $this->mockSessionEndingAt('session-42', $this->secondsFromNow($idleIn), $this->secondsFromNow($absoluteIn));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a session that has ended or that has no idle deadline.');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, $record);
    }

    /**
     * No refresh token is issued for a session that has ended or has no idle
     * deadline, so issuing cannot extend a session that is over.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @return void
     */
    #[DataProvider('provideEndedSessions')]
    public function testRefusesARefreshTokenForAnEndedSession(?int $idleIn, ?int $absoluteIn): void
    {
        $record = $this->mockSessionEndingAt('session-42', $this->secondsFromNow($idleIn), $this->secondsFromNow($absoluteIn));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a session that has ended or that has no idle deadline.');

        $this->makeService()->issueRefreshToken($record, 'rotation-id');
    }

    /**
     * A session-less access token carries exactly the access claims, and a
     * client credentials token those and its `cid` and `scope`, with no session
     * and the subject type `machine`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientTokenAddsOnlyItsCredentialClaims(): void
    {
        $service = $this->makeService();
        $access  = ['iss', 'aud', 'client_id', 'sub', 'sub_type', 'principal', 'jti', 'iat', 'exp'];

        $session = $service->parse($service->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, null), TokenType::ACCESS);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\MachineIdentity $machine */
        $machine = \Mockery::mock(MachineIdentity::class);
        $machine->shouldReceive('getAuthIdentifier')->andReturn('machine-7');

        $client = $service->parse($service->issueClientAccessToken($machine, $this->mockPrincipal('principal-3'), null, self::KEY_ID, ['read']), TokenType::ACCESS);

        self::assertIsArray($session);
        self::assertIsArray($client);
        self::assertEqualsCanonicalizing($access, array_keys($session));
        self::assertEqualsCanonicalizing([...$access, 'cid', 'scope'], array_keys($client));
        self::assertSame(['person', 'machine'], [$session['sub_type'], $client['sub_type']]);
        self::assertSame([self::KEY_ID, 'read', 'machine-7'], [$client['cid'], $client['scope'], $client['sub']]);
    }

    /**
     * A client credentials token carries the tenant the exchange's admission
     * loaded, stringified.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientTokenCarriesItsTenant(): void
    {
        $service = $this->makeService();

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\MachineIdentity $machine */
        $machine = \Mockery::mock(MachineIdentity::class);
        $machine->shouldReceive('getAuthIdentifier')->andReturn('machine-7');

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant $tenant */
        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn(12);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('principal-3');
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        $client = $service->parse($service->issueClientAccessToken($machine, $principal, $tenant, self::KEY_ID, []), TokenType::ACCESS);

        self::assertIsArray($client);
        self::assertSame('12', $client[Claims::TENANT_ID->value]);
    }

    /**
     * Rows of `[claims to merge into a session's access token, claims to
     * remove]` that break the access token's shape.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideMisshapenAccessTokens(): iterable
    {
        yield from [
            'machine subject without a key' => [['sub_type' => 'machine'], []],
            'unknown subject type'          => [['sub_type' => 'service'], []],
            'no auth_time with a session'   => [[], ['auth_time']],
            'no amr with a session'         => [[], ['amr']],
            'auth_time as a string'         => [['auth_time' => '1775476800'], []],
            'amr as an object'              => [['amr' => ['first' => 'pwd']], []],
            'amr holding an empty string'   => [['amr' => ['pwd', '']], []],
            'amr holding a number'          => [['amr' => [7]], []],
            'amr as a string'               => [['amr' => 'pwd'], []],
            'empty tenant'                  => [['tenant_id' => ''], []],
            'numeric tenant'                => [['tenant_id' => 9], []],
            'null tenant'                   => [['tenant_id' => null], []],
        ];
    }

    /**
     * An access token that breaks the profile's shape is rejected, whether or
     * not a type is expected.
     *
     * @param  array<string, mixed>  $merge
     * @param  list<string>  $remove
     * @return void
     */
    #[DataProvider('provideMisshapenAccessTokens')]
    public function testParseRejectsAMisshapenAccessToken(array $merge, array $remove): void
    {
        $claims = [...$this->completeClaims(TokenType::ACCESS), ...$merge];

        foreach ($remove as $name) {
            unset($claims[$name]);
        }

        self::assertNull($this->makeService()->parse($this->encode($claims), TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($this->encode($claims)));
    }

    /**
     * A session-less access token carries neither `auth_time` nor `amr`: one
     * that does is rejected.
     *
     * @return void
     */
    public function testParseRejectsAuthenticationClaimsWithoutASession(): void
    {
        $sessionless = $this->sessionless($this->completeClaims(TokenType::ACCESS));

        self::assertIsArray($this->makeService()->parse($this->encode($sessionless), TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($this->encode([...$sessionless, Claims::AUTH_TIME->value => $this->now->getTimestamp()]), TokenType::ACCESS));
        self::assertNull($this->makeService()->parse($this->encode([...$sessionless, Claims::AUTHENTICATION_METHODS->value => []]), TokenType::ACCESS));
    }

    /**
     * The well-formed edges of the shape parse: an empty `amr`, an `auth_time`
     * at the leeway's edge after the issue time, and a tenant; an `auth_time` a
     * second past that edge does not.
     *
     * @return void
     */
    public function testParseAcceptsTheEdgesOfTheShape(): void
    {
        $claims = $this->completeClaims(TokenType::ACCESS);
        $edges  = [
            [Claims::AUTHENTICATION_METHODS->value => []],
            [Claims::AUTH_TIME->value => $this->now->getTimestamp() + 30],
            [Claims::TENANT_ID->value => 'tenant-9'],
        ];

        foreach ($edges as $edge) {
            self::assertIsArray($this->makeService()->parse($this->encode([...$claims, ...$edge]), TokenType::ACCESS));
        }

        self::assertNull($this->makeService()->parse($this->encode([...$claims, Claims::AUTH_TIME->value => $this->now->getTimestamp() + 31]), TokenType::ACCESS));
    }

    /**
     * A token that breaks the shape is debug-logged with why, and its type.
     *
     * @return void
     */
    public function testParseLogsAMisshapenAccessToken(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);

        foreach (['JWT subject type mismatch', 'JWT authentication claims malformed', 'JWT tenant claim malformed'] as $message) {
            $logger->shouldReceive('debug')->once()->with($message, ['typ' => 'at+jwt']);
        }

        $service = $this->makeServiceWithLogger($logger);
        $claims  = $this->completeClaims(TokenType::ACCESS);

        self::assertNull($service->parse($this->encode([...$claims, Claims::SUBJECT_TYPE->value => 'machine']), TokenType::ACCESS));
        self::assertNull($service->parse($this->encode([...$claims, Claims::AUTHENTICATION_METHODS->value => 'pwd']), TokenType::ACCESS));
        self::assertNull($service->parse($this->encode([...$claims, Claims::TENANT_ID->value => '']), TokenType::ACCESS));
    }

    /**
     * A refresh token naming an API key is rejected: a key's token has no
     * session, and a refresh token always names one.
     *
     * @return void
     */
    public function testParseRejectsARefreshTokenNamingAnApiKey(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT credential claims malformed', ['typ' => 'refresh+jwt']);

        $claims = [...$this->completeClaims(TokenType::REFRESH), Claims::CREDENTIAL_ID->value => self::KEY_ID, Claims::SCOPE->value => 'read'];

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims, TokenType::REFRESH), TokenType::REFRESH));
    }

    /**
     * A token whose credential claims are out of form is debug-logged with the
     * claims that must agree.
     *
     * @return void
     */
    public function testParseLogsMalformedCredentialClaims(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->once()
            ->with('JWT credential claims malformed', ['typ' => 'at+jwt']);

        $claims = [
            ...$this->completeClaims(TokenType::ACCESS),
            Claims::CREDENTIAL_ID->value => self::KEY_ID,
            Claims::SCOPE->value         => 'read',
            Claims::SUBJECT_TYPE->value  => 'machine',
        ];

        self::assertNull($this->makeServiceWithLogger($logger)->parse($this->encode($claims), TokenType::ACCESS));
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
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );
    }

    /**
     * Build a complete, valid claim set for the token type: a session's access
     * token, or a refresh token naming its principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     */
    private function completeClaims(TokenType $type): array
    {
        $claims = [
            Claims::ISSUER->value     => self::ISSUER,
            Claims::AUDIENCE->value   => self::AUDIENCE,
            Claims::CLIENT_ID->value  => self::GUARD,
            Claims::PRINCIPAL->value  => 'principal-3',
            Claims::SESSION_ID->value => 'session-42',
            Claims::JWT_ID->value     => 'token-id',
            Claims::ISSUED_AT->value  => $this->now->getTimestamp(),
            Claims::EXPIRES_AT->value => $this->now->getTimestamp() + 600,
        ];

        if ($type === TokenType::ACCESS) {
            $claims += [
                Claims::SUBJECT->value                => 'identity-7',
                Claims::SUBJECT_TYPE->value           => 'person',
                Claims::AUTH_TIME->value              => $this->now->getTimestamp() - 60,
                Claims::AUTHENTICATION_METHODS->value => ['pwd'],
            ];
        }

        return $claims;
    }

    /**
     * The claims without the session and the authentication that comes with it,
     * as an access-only token carries them.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    private function sessionless(array $claims): array
    {
        unset($claims[Claims::SESSION_ID->value], $claims[Claims::AUTH_TIME->value], $claims[Claims::AUTHENTICATION_METHODS->value]);

        return $claims;
    }

    /**
     * Sign the claims with the shared test key, as a token of the type.
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return string
     */
    private function encode(array $claims, TokenType $type = TokenType::ACCESS): string
    {
        return JWT::encode($claims, self::SECRET, self::ALGORITHM, self::KID, ['typ' => $type->value]);
    }

    /**
     * Sign the claims with the shared test key under exactly the given header,
     * which php-jwt would otherwise give a `typ` of its own.
     *
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function sign(array $header, array $claims): string
    {
        $signed = JWT::urlsafeB64Encode((string) json_encode($header)) . '.' . JWT::urlsafeB64Encode((string) json_encode($claims));

        return $signed . '.' . JWT::urlsafeB64Encode(JWT::sign($signed, self::SECRET, self::ALGORITHM));
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
            new TokenLifetimes(self::ACCESS_TTL_MINUTES, self::REFRESH_TTL_MINUTES, self::ABSOLUTE_TTL_MINUTES, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
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
}
