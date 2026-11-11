<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Issues a session's token pair for the session service and the refresh
 * exchange.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionTokens
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Issue the session's body-transport pair at `$now` inside the issuer's
     * transaction.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $inserted
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenPair
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public static function pair(
        JwtTokenService $tokens,
        Admitted $admitted,
        EloquentSession&Model $session,
        #[\SensitiveParameter]
        string $rotationId,
        CarbonImmutable $now,
        bool $inserted = false,
    ): TokenPair {
        $access = $tokens->issueGuardedAccessToken($admitted->identity, $admitted->principal, $admitted->tenant, $session, $now, $inserted);

        return new TokenPair(
            accessToken: $access->token,
            expiresAt: $access->expiresAt,
            expiresIn: $access->expiresIn,
            refreshToken: $tokens->issueRefreshToken($session, $rotationId, $admitted->principal, $now),
        );
    }
}
