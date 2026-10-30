<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * How checking a code that verifies an identifier ended: what the verifier
 * answered once the code was accepted, or why the code was not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum VerificationOutcome: string
{
    // The code was accepted and the identifier recorded verified by this call
    case VERIFIED = 'verified';

    // The code was accepted, and the identifier, still the identity's, was
    // verified before
    case ALREADY_VERIFIED = 'already_verified';

    // The code was accepted and used up, but the identifier is no longer the
    // identity's current one, so nothing was recorded
    case MISMATCH = 'mismatch';

    // No live code was issued for the identity's current identifier, it was
    // used up or replaced, the code is malformed or does not match, or the
    // identity has no identifier of the type
    case INVALID = 'invalid';

    // The code has expired
    case EXPIRED = 'expired';

    // The code has used up its attempts
    case EXHAUSTED = 'exhausted';
}
