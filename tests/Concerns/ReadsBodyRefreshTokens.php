<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;

/**
 * Reads the refresh token a body application's tokens carry, failing the test
 * when they carry it in a cookie instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsBodyRefreshTokens
{
    /**
     * The refresh token a body application's tokens carry, as a controller
     * reads it from a request body (`PresentedRefreshToken::fromBody()`) to
     * hand on to the session service.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken
     */
    protected static function bodyToken(?TokenPair $tokens): PresentedRefreshToken
    {
        $token = $tokens?->refreshToken;

        self::assertNotNull($token, 'The tokens carry no refresh token in the body.');

        return PresentedRefreshToken::fromBody($token);
    }

    /**
     * The refresh token a body application's tokens carry, revealed.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return string
     */
    protected static function bodyRefreshToken(?TokenPair $tokens): string
    {
        $token = $tokens?->refreshToken;

        self::assertNotNull($token, 'The tokens carry no refresh token in the body.');

        return $token->reveal();
    }
}
