<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * The JWT claim keys the package reads and writes, mapped to their wire names.
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
