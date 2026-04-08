<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Canonical JWT claim keys used by the package.
 *
 * Kept as class constants rather than string literals so the refresh
 * flow and access-token issuance paths cannot drift out of sync.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Claims
{
    /** @var string Standard `sub` claim — identity identifier (stringified). */
    public const string SUBJECT = 'sub';

    /** @var string Standard `iss` claim — issuer string, if configured. */
    public const string ISSUER = 'iss';

    /** @var string Standard `aud` claim — audience string, if configured. */
    public const string AUDIENCE = 'aud';

    /** @var string Standard `iat` claim — issued-at, unix seconds. */
    public const string ISSUED_AT = 'iat';

    /** @var string Standard `exp` claim — expiry, unix seconds. */
    public const string EXPIRES_AT = 'exp';

    /** @var string Standard `jti` claim — unique token id, used as the refresh-credential rotation token. */
    public const string JWT_ID = 'jti';

    /** @var string Package `typ` claim — token type (`access` or `refresh`). */
    public const string TYPE = 'typ';

    /** @var string Package `pid` claim — principal identifier (stringified). */
    public const string PRINCIPAL_ID = 'pid';

    /** @var string Package `did` claim — device identifier (stringified). */
    public const string DEVICE_ID = 'did';

    /** @var string `typ` value marking an access token. */
    public const string TYPE_ACCESS = 'access';

    /** @var string `typ` value marking a refresh token. */
    public const string TYPE_REFRESH = 'refresh';

    /**
     * Disallow instantiation: container for constants only.
     */
    private function __construct() {}
}
