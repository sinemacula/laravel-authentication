<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * JWT token type.
 *
 * Backed enum distinguishing access tokens from refresh tokens. Used as the
 * `typ` claim value and as the type-safe parameter for
 * `JwtTokenService::parse()` so callers cannot pass a typo'd string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TokenType: string
{
    case ACCESS  = 'access';
    case REFRESH = 'refresh';
}
