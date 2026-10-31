<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Verification\Enums;

/**
 * How consuming a verification link ended: what the verifier answered once the
 * link was accepted, or why the link was not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum VerificationLinkOutcome: string
{
    // The link was accepted and the identifier recorded verified by this call
    case VERIFIED = 'verified';

    // The link was accepted, and the identifier, still the identity's, was
    // verified before
    case ALREADY_VERIFIED = 'already_verified';

    // The link was accepted, but the identifier changed while it was being
    // verified, so nothing was recorded
    case MISMATCH = 'mismatch';

    // The link is malformed, tampered with or signed for something else, or
    // names no guard, identity or current identifier it proves
    case INVALID = 'invalid';

    // The link is authentic but its time has passed
    case EXPIRED = 'expired';
}
