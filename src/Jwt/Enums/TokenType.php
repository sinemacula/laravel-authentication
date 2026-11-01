<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * JWT token type.
 *
 * Backed enum distinguishing access tokens from refresh tokens. Its value is
 * the token's JOSE header `typ`: `at+jwt` for an access token (RFC 9068 §2.1)
 * and the private `refresh+jwt` for a refresh token, so neither can be
 * presented as the other. It is also the type-safe parameter for
 * `JwtTokenService::parse()`, so callers cannot pass a typo'd string, and owns
 * the set of claims each type must carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TokenType: string
{
    case ACCESS  = 'at+jwt';
    case REFRESH = 'refresh+jwt';

    /**
     * Claims a token of this type must carry with a non-empty value; an access
     * token's `sid` stays optional for access-only mode and client credentials
     * tokens.
     *
     * @return list<\SineMacula\Laravel\Authentication\Jwt\Enums\Claims>
     */
    public function requiredClaims(): array
    {
        $common = [Claims::ISSUER, Claims::AUDIENCE, Claims::CLIENT_ID, Claims::JWT_ID, Claims::ISSUED_AT, Claims::EXPIRES_AT];

        return match ($this) {
            self::ACCESS  => [...$common, Claims::SUBJECT, Claims::SUBJECT_TYPE, Claims::PRINCIPAL],
            self::REFRESH => [...$common, Claims::SESSION_ID],
        };
    }
}
