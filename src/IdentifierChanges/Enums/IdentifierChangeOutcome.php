<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges\Enums;

/**
 * How confirming a change of identifier ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IdentifierChangeOutcome: string
{
    // The identifier was replaced by the new one, recorded as verified
    case CHANGED = 'changed';

    // No change of this guard waits, the proof does not match it, the
    // identifier changed meanwhile, or the identity is not active
    case INVALID = 'invalid';

    // The pending change, its code or its link has expired
    case EXPIRED = 'expired';

    // The code used up its attempts; the change must be requested again
    case EXHAUSTED = 'exhausted';

    // Another identity holds the new identifier; the proof was not used up
    case TAKEN = 'taken';

    // The identity or the IP address has used up its confirmations
    case RATE_LIMITED = 'rate_limited';
}
