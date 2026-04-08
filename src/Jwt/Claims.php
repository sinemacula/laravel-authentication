<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Canonical JWT claim keys used by the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Claims
{
    /** @var string Standard `sub` claim - identity identifier. */
    public const string SUBJECT = 'sub';

    /** @var string Standard `iss` claim - issuer string. */
    public const string ISSUER = 'iss';

    /** @var string Standard `aud` claim - audience string. */
    public const string AUDIENCE = 'aud';

    /** @var string Standard `iat` claim - issued-at, unix seconds. */
    public const string ISSUED_AT = 'iat';

    /** @var string Standard `exp` claim - expiry, unix seconds. */
    public const string EXPIRES_AT = 'exp';

    /** @var string Standard `jti` claim - rotation token id. */
    public const string JWT_ID = 'jti';

    /** @var string Package `typ` claim - token type. */
    public const string TYPE = 'typ';

    /** @var string Package `pid` claim - principal identifier. */
    public const string PRINCIPAL_ID = 'pid';

    /** @var string Package `did` claim - device identifier. */
    public const string DEVICE_ID = 'did';

    /** @var string `typ` value marking an access token. */
    public const string TYPE_ACCESS = 'access';

    /** @var string `typ` value marking a refresh token. */
    public const string TYPE_REFRESH = 'refresh';

    /**
     * Disallow instantiation; constants only.
     */
    private function __construct() {}
}
