<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\TokenProfile;

/**
 * Unit tests for the token profile's shape rules: the type a header `typ`
 * names, and what an access token's claims must say about its subject, its
 * session and its tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenProfile::class)]
final class TokenProfileTest extends TestCase
{
    /** @var int The issue time every claim set here carries. */
    private const int ISSUED_AT = 1000000;

    /** @var int The leeway the shape is judged with. */
    private const int LEEWAY = 30;

    /** @var string An API key id. */
    private const string KEY_ID = '0195f4a2-7b1c-7000-8000-000000000001';

    /**
     * Rows of `[header typ, the type it names or null]`.
     *
     * @return iterable<string, array{0: mixed, 1: ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType}>
     */
    public static function provideHeaderTypes(): iterable
    {
        yield from [
            'access'               => ['at+jwt', TokenType::ACCESS],
            'access in upper case' => ['AT+JWT', TokenType::ACCESS],
            'access media type'    => ['application/at+jwt', TokenType::ACCESS],
            'access upper prefix'  => ['APPLICATION/AT+JWT', TokenType::ACCESS],
            'refresh'              => ['refresh+jwt', TokenType::REFRESH],
            'refresh media type'   => ['application/refresh+jwt', TokenType::REFRESH],
            'php-jwt default'      => ['JWT', null],
            'prefix only'          => ['application/', null],
            'prefix inside'        => ['xapplication/at+jwt', null],
            'prefix doubled'       => ['application/application/at+jwt', null],
            'suffix'               => ['at+jwt/application', null],
            'trailing space'       => ['at+jwt ', null],
            'empty'                => ['', null],
            'integer'              => [7, null],
            'array'                => [['at+jwt'], null],
            'null'                 => [null, null],
        ];
    }

    /**
     * A header type names its token type without regard to case and with or
     * without the `application/` prefix; anything else names none.
     *
     * @param  mixed  $typ
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expected
     * @return void
     */
    #[DataProvider('provideHeaderTypes')]
    public function testHeaderTypeNamesItsTokenType(mixed $typ, ?TokenType $expected): void
    {
        self::assertSame($expected, TokenProfile::headerType($typ));
    }

    /**
     * Rows of `[claims, the failure or null]` for access token claim sets.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?string}>
     */
    public static function provideAccessClaims(): iterable
    {
        $session = ['sub_type' => 'person', 'sid' => 'session-42', 'auth_time' => self::ISSUED_AT - 60, 'amr' => ['pwd'], 'iat' => self::ISSUED_AT];
        $client  = ['sub_type' => 'machine', 'cid' => self::KEY_ID, 'scope' => 'read', 'iat' => self::ISSUED_AT];

        yield from [
            'a session token'                    => [$session, null],
            'a session-less person token'        => [['sub_type' => 'person', 'iat' => self::ISSUED_AT], null],
            'a null session'                     => [['sub_type' => 'person', 'sid' => null, 'iat' => self::ISSUED_AT], null],
            'a client credentials token'         => [$client, null],
            'a tenant'                           => [[...$session, 'tenant_id' => 'tenant-9'], null],
            'an empty amr'                       => [[...$session, 'amr' => []], null],
            'an auth_time at the leeway'         => [[...$session, 'auth_time' => self::ISSUED_AT + self::LEEWAY], null],
            'a malformed key'                    => [[...$client, 'cid' => 'key-1'], 'JWT credential claims malformed'],
            'a key with a session'               => [[...$client, 'sid' => 'session-42', 'auth_time' => self::ISSUED_AT, 'amr' => []], 'JWT credential claims malformed'],
            'a person naming a key'              => [[...$client, 'sub_type' => 'person'], 'JWT subject type mismatch'],
            'a machine naming no key'            => [[...$session, 'sub_type' => 'machine'], 'JWT subject type mismatch'],
            'an unknown subject type'            => [[...$session, 'sub_type' => 'service'], 'JWT subject type mismatch'],
            'no subject type'                    => [['sid' => 'session-42', 'auth_time' => self::ISSUED_AT, 'amr' => [], 'iat' => self::ISSUED_AT], 'JWT subject type mismatch'],
            'an auth_time past the leeway'       => [[...$session, 'auth_time' => self::ISSUED_AT + self::LEEWAY + 1], 'JWT authentication claims malformed'],
            'a string auth_time'                 => [[...$session, 'auth_time' => (string) self::ISSUED_AT], 'JWT authentication claims malformed'],
            'a float auth_time'                  => [[...$session, 'auth_time' => self::ISSUED_AT - 0.5], 'JWT authentication claims malformed'],
            'a float issue time'                 => [[...$session, 'iat' => self::ISSUED_AT + 0.5], 'JWT authentication claims malformed'],
            'no issue time'                      => [array_diff_key($session, ['iat' => true]), 'JWT authentication claims malformed'],
            'no auth_time'                       => [array_diff_key($session, ['auth_time' => true]), 'JWT authentication claims malformed'],
            'no amr'                             => [array_diff_key($session, ['amr' => true]), 'JWT authentication claims malformed'],
            'an amr that is a map'               => [[...$session, 'amr' => ['first' => 'pwd']], 'JWT authentication claims malformed'],
            'an amr with an empty method'        => [[...$session, 'amr' => ['pwd', '']], 'JWT authentication claims malformed'],
            'an amr with a number'               => [[...$session, 'amr' => ['pwd', 7]], 'JWT authentication claims malformed'],
            'an amr that is a string'            => [[...$session, 'amr' => 'pwd'], 'JWT authentication claims malformed'],
            'an auth_time without a session'     => [['sub_type' => 'person', 'auth_time' => self::ISSUED_AT, 'iat' => self::ISSUED_AT], 'JWT authentication claims malformed'],
            'an amr without a session'           => [['sub_type' => 'person', 'amr' => [], 'iat' => self::ISSUED_AT], 'JWT authentication claims malformed'],
            'a null auth_time without a session' => [['sub_type' => 'person', 'auth_time' => null, 'iat' => self::ISSUED_AT], 'JWT authentication claims malformed'],
            'an empty tenant'                    => [[...$session, 'tenant_id' => ''], 'JWT tenant claim malformed'],
            'a numeric tenant'                   => [[...$session, 'tenant_id' => 9], 'JWT tenant claim malformed'],
            'a null tenant'                      => [[...$session, 'tenant_id' => null], 'JWT tenant claim malformed'],
            'a tenant on a client token'         => [[...$client, 'tenant_id' => 'tenant-9'], null],
        ];
    }

    /**
     * An access token keeps the profile's shape, or the first rule it breaks is
     * named, in the order key, subject type, authentication, tenant.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideAccessClaims')]
    public function testAccessFailureNamesTheRuleTheClaimsBreak(array $claims, ?string $expected): void
    {
        self::assertSame($expected, TokenProfile::accessFailure($claims, self::LEEWAY));
    }

    /**
     * The leeway the shape is judged with is the one given: an `auth_time` a
     * second after the issue time fails without leeway and passes with it.
     *
     * @return void
     */
    public function testAccessFailureAppliesTheGivenLeeway(): void
    {
        $claims = ['sub_type' => 'person', 'sid' => 'session-42', 'auth_time' => self::ISSUED_AT + 1, 'amr' => [], 'iat' => self::ISSUED_AT];

        self::assertSame('JWT authentication claims malformed', TokenProfile::accessFailure($claims, 0));
        self::assertNull(TokenProfile::accessFailure($claims, 1));
    }

    /**
     * The constructor is private: the profile holds no state.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TokenProfile::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TokenProfile::class, $instance);
    }
}
