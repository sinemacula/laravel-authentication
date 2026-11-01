<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;

/**
 * Unit tests for the `TokenType` enum and the claims each type requires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenType::class)]
final class TokenTypeTest extends TestCase
{
    /**
     * Each type's value is its JOSE header type: RFC 9068's `at+jwt` for an
     * access token and the private `refresh+jwt` for a refresh token.
     *
     * @return void
     */
    public function testEveryTypeIsItsHeaderType(): void
    {
        self::assertSame([TokenType::ACCESS, TokenType::REFRESH], TokenType::cases());
        self::assertSame(['at+jwt', 'refresh+jwt'], [TokenType::ACCESS->value, TokenType::REFRESH->value]);
    }

    /**
     * Both types require `iss`, `aud`, `client_id`, `jti`, `iat` and `exp`, in
     * that order.
     *
     * @return void
     */
    public function testEveryTypeRequiresTheCommonClaims(): void
    {
        $common = [Claims::ISSUER, Claims::AUDIENCE, Claims::CLIENT_ID, Claims::JWT_ID, Claims::ISSUED_AT, Claims::EXPIRES_AT];

        foreach (TokenType::cases() as $type) {
            self::assertSame($common, array_slice($type->requiredClaims(), 0, count($common)));
        }
    }

    /**
     * An access token also requires `sub`, `sub_type` and `principal`, and not
     * `sid`.
     *
     * @return void
     */
    public function testAccessTokensRequireSubjectAndPrincipal(): void
    {
        self::assertSame(
            [Claims::ISSUER, Claims::AUDIENCE, Claims::CLIENT_ID, Claims::JWT_ID, Claims::ISSUED_AT, Claims::EXPIRES_AT, Claims::SUBJECT, Claims::SUBJECT_TYPE, Claims::PRINCIPAL],
            TokenType::ACCESS->requiredClaims(),
        );
    }

    /**
     * A refresh token also requires `sid`, and not `sub` or `principal`.
     *
     * @return void
     */
    public function testRefreshTokensRequireSession(): void
    {
        self::assertSame(
            [Claims::ISSUER, Claims::AUDIENCE, Claims::CLIENT_ID, Claims::JWT_ID, Claims::ISSUED_AT, Claims::EXPIRES_AT, Claims::SESSION_ID],
            TokenType::REFRESH->requiredClaims(),
        );
    }
}
