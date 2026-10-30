<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords\Enums;

/**
 * How a password reset ended. An unknown identifier, a wrong, expired or used
 * token or code, and an identity that may not reset its password are all
 * `invalid`, so the answer does not say which.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ResetStatus: string
{
    // The password was set and every session of the identity ended
    case RESET = 'reset';

    // The identifier, token or code was not accepted, or the identity may not
    // reset its password
    case INVALID = 'invalid';

    // The identifier or the IP address has used up its resets for now
    case RATE_LIMITED = 'rate_limited';

    // The new password breaks the password policy; nothing was used up
    case PASSWORD_REJECTED = 'password_rejected';
}
