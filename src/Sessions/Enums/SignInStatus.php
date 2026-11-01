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
    // A session started: the result carries the session and the token pair
    case SIGNED_IN = 'signed_in';

    // The session waits on requirements: the result carries the pending
    // session, and its credential when the call issued one
    case PENDING = 'pending';

    // The sign-in failed: the result carries the reason
    case FAILED = 'failed';
}
