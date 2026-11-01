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
 * The package's own profile, borrowing RFC 9068's claims without claiming its
 * conformance (which needs asymmetric keys): every token carries `iss`, `aud`
 * and `client_id` (the application, which is the guard that issued it). An
 * access token names its subject in `sub` with its kind in `sub_type`, the
 * principal it acts as in `principal`, and, when it belongs to a session, the
 * session in `sid` with the time of the session's latest authentication in
 * `auth_time` and the methods it used in `amr`; `tenant_id` names the tenant
 * the principal acts within. A refresh token names its session in `sid`. An
 * access token a client credentials exchange issued carries the API key's id in
 * `cid` and the scopes it grants, space-separated, in `scope`. The token's type
 * is its JOSE header's `typ`, not a claim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Claims: string
{
    case ISSUER                 = 'iss';
    case AUDIENCE               = 'aud';
    case SUBJECT                = 'sub';
    case SUBJECT_TYPE           = 'sub_type';
    case CLIENT_ID              = 'client_id';
    case PRINCIPAL              = 'principal';
    case SESSION_ID             = 'sid';
    case TENANT_ID              = 'tenant_id';
    case AUTH_TIME              = 'auth_time';
    case AUTHENTICATION_METHODS = 'amr';
    case JWT_ID                 = 'jti';
    case ISSUED_AT              = 'iat';
    case EXPIRES_AT             = 'exp';
    case CREDENTIAL_ID          = 'cid';
    case SCOPE                  = 'scope';
}
