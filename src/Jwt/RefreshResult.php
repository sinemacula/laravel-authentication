<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Immutable token pair returned by a refresh exchange.
 *
 * The old refresh token is burned server-side during the exchange,
 * so consumers must replace their stored credential with the value
 * in `$refreshToken` immediately - the previous value will no longer
 * authenticate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RefreshResult
{
    /**
     * Constructor.
     *
     * @param  string  $accessToken
     * @param  string  $refreshToken
     */
    public function __construct(
        #[\SensitiveParameter] public string $accessToken,
        #[\SensitiveParameter] public string $refreshToken,
    ) {}
}
