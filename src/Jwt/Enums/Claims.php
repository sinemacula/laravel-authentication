<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * Canonical JWT claim keys used by the package.
 *
 * Backed enum mapping each case to its wire-format claim name. Use
 * `Claims::CASE->value` whenever the claim name is needed as an array key
 * against the JWT payload (which is `array<string, mixed>`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Claims: string
{
    case SUBJECT      = 'sub';
    case ISSUER       = 'iss';
    case AUDIENCE     = 'aud';
    case ISSUED_AT    = 'iat';
    case EXPIRES_AT   = 'exp';
    case JWT_ID       = 'jti';
    case TYPE         = 'typ';
    case PRINCIPAL_ID = 'pid';
    case DEVICE_ID    = 'did';
}
