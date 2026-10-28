<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * How a request for a one-time code ended. A sign-in code is sent whether or
 * not any identity has the identifier, so `sent` never says that one does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CodeRequestStatus: string
{
    // A code was issued and its delivery queued
    case SENT = 'sent';

    // The identifier or the IP address has used up its code requests for now,
    // or a code was issued for the identifier within the resend cooldown
    case RATE_LIMITED = 'rate_limited';

    // The guard does not allow the code sign-in method
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The identifier is not one the type's normaliser accepts, or the identity
    // has no identifier of the type to verify
    case IDENTIFIER_INVALID = 'identifier_invalid';
}
