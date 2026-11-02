<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * Whether a session is active, holding a token pair, or pending, waiting on the
 * requirements it lists with only a pending credential. Revocation is recorded
 * apart, on either.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SessionStatus: string
{
    // The session holds a token pair and authenticates requests
    case ACTIVE = 'active';

    // The session waits on requirements: no access or refresh token of it is
    // accepted until it activates
    case PENDING = 'pending';
}
