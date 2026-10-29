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
 * `typ` is the token's type (access or refresh); the principal's type travels
 * in `pty`, which an access token carries only when the principal has one. An
 * access token a client credentials exchange issued carries the API key's id in
 * `cid` and the scopes it grants, space-separated, in `scope`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Claims: string
{
    case SUBJECT        = 'sub';
    case ISSUER         = 'iss';
    case AUDIENCE       = 'aud';
    case ISSUED_AT      = 'iat';
    case EXPIRES_AT     = 'exp';
    case JWT_ID         = 'jti';
    case TYPE           = 'typ';
    case PRINCIPAL_ID   = 'pid';
    case PRINCIPAL_TYPE = 'pty';
    case DEVICE_ID      = 'did';
    case GUARD          = 'grd';
    case CREDENTIAL_ID  = 'cid';
    case SCOPE          = 'scope';
}
