<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting\Enums;

/**
 * A flow whose attempts the package limits; its value names the flow's block in
 * the `rate_limits` configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AttemptFlow: string
{
    // Signing in with a sign-in method
    case SIGN_IN = 'sign_in';

    // Exchanging a refresh token
    case REFRESH = 'refresh';
}
