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
     * Both types require `exp`, `iat`, `jti`, `typ`, and the guard claim, in
     * that order.
     *
     * @return void
     */
    public function testEveryTypeRequiresTheCommonClaims(): void
    {
        $common = [Claims::EXPIRES_AT, Claims::ISSUED_AT, Claims::JWT_ID, Claims::TYPE, Claims::GUARD];

        foreach (TokenType::cases() as $type) {
            self::assertSame($common, array_slice($type->requiredClaims(), 0, count($common)));
        }
    }

    /**
     * An access token also requires `sub` and `pid`, and not `did`.
     *
     * @return void
     */
    public function testAccessTokensRequireSubjectAndPrincipal(): void
    {
        self::assertSame(
            [Claims::EXPIRES_AT, Claims::ISSUED_AT, Claims::JWT_ID, Claims::TYPE, Claims::GUARD, Claims::SUBJECT, Claims::PRINCIPAL_ID],
            TokenType::ACCESS->requiredClaims(),
        );
    }

    /**
     * A refresh token also requires `did`, and not `sub` or `pid`.
     *
     * @return void
     */
    public function testRefreshTokensRequireDevice(): void
    {
        self::assertSame(
            [Claims::EXPIRES_AT, Claims::ISSUED_AT, Claims::JWT_ID, Claims::TYPE, Claims::GUARD, Claims::DEVICE_ID],
            TokenType::REFRESH->requiredClaims(),
        );
    }
}
