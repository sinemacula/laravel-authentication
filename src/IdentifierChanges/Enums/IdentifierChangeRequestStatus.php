<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges\Enums;

/**
 * How a request to change an identifier ended. A change is requested whether or
 * not another identity holds the new identifier, so `sent` never says that none
 * does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IdentifierChangeRequestStatus: string
{
    // The change waits for its proof: a code was issued and its delivery
    // queued, or a link was signed
    case SENT = 'sent';

    // The new identifier, the identity or the IP address has used up its change
    // requests for now, or the password given to reauthenticate was checked too
    // often
    case RATE_LIMITED = 'rate_limited';

    // The identity did not authenticate recently enough, or the password given
    // to reauthenticate was wrong
    case REAUTHENTICATION_REQUIRED = 'reauthentication_required';

    // The new identifier is not one the type's normaliser accepts
    case IDENTIFIER_INVALID = 'identifier_invalid';

    // The new identifier is the identity's current one, in its normal form
    case IDENTIFIER_UNCHANGED = 'identifier_unchanged';
}
