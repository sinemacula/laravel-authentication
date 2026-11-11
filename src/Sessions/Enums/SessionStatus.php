<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * Whether a session is active or pending; revocation is recorded apart.
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

    // The session waits on requirements and accepts no token until it activates
    case PENDING = 'pending';
}
