<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * JWT token type.
 *
 * Backed enum distinguishing access tokens from refresh tokens. Used as the
 * `typ` claim value and as the type-safe parameter for
 * `JwtTokenService::parse()` so callers cannot pass a typo'd string, and owns
 * the set of claims each type must carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TokenType: string
{
    case ACCESS  = 'access';
    case REFRESH = 'refresh';

    /**
     * Claims a token of this type must carry with a non-empty value. Both types
     * need `exp`, `iat`, `jti`, `typ`, and the guard claim; an access token
     * also needs `sub` and `pid` (`did` stays optional for access-only mode),
     * and a refresh token needs `did`.
     *
     * @return list<\SineMacula\Laravel\Authentication\Jwt\Enums\Claims>
     */
    public function requiredClaims(): array
    {
        $common = [Claims::EXPIRES_AT, Claims::ISSUED_AT, Claims::JWT_ID, Claims::TYPE, Claims::GUARD];

        return match ($this) {
            self::ACCESS  => [...$common, Claims::SUBJECT, Claims::PRINCIPAL_ID],
            self::REFRESH => [...$common, Claims::DEVICE_ID],
        };
    }
}
