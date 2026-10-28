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

    // A further factor is required: the result carries the pending sign-in
    case FACTOR_REQUIRED = 'factor_required';

    // The identity must choose the principal to act as: the result carries the
    // choice
    case PRINCIPAL_REQUIRED = 'principal_required';

    // The sign-in failed: the result carries the reason
    case FAILED = 'failed';
}
