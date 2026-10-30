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

    // No change of this guard is pending, it was replaced by a newer request or
    // already confirmed, the code or link does not prove it, the identifier
    // changed by another path since it was requested, or the identity is not
    // active
    case INVALID = 'invalid';

    // The pending change, its code or its link has expired
    case EXPIRED = 'expired';

    // The code used up its attempts; the change must be requested again
    case EXHAUSTED = 'exhausted';

    // Another identity holds the new identifier; the proof was not used up
    case TAKEN = 'taken';
}
