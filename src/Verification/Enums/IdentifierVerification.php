<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Verification\Enums;

/**
 * The outcome of verifying an identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IdentifierVerification: string
{
    // The identifier was verified by this call
    case VERIFIED = 'verified';

    // The identifier is the identity's current one and was verified before
    case ALREADY_VERIFIED = 'already_verified';

    // The identifier is not the identity's current one, so it was not verified
    case MISMATCH = 'mismatch';
}
