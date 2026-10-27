<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * How a sign-in through the session service ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SignInStatus: string
{
    // A session started: the result carries the device and the token pair
    case SIGNED_IN = 'signed_in';

    // The sign-in failed: the result carries the reason
    case FAILED = 'failed';
}
