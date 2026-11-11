<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * A JWT's type, carried as its JOSE header `typ` so neither type can be
 * presented as the other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TokenType: string
{
    case ACCESS  = 'at+jwt';
    case REFRESH = 'refresh+jwt';

    /**
     * Claims a token of this type must carry with a non-empty value.
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
