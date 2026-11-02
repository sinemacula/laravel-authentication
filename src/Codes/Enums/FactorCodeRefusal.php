<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * Why the factor package refused to have a factor code sent or checked. The
 * values are the factor package's own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorCodeRefusal: string
{
    // The factor named is not one the factor package knows
    case NOT_FOUND = 'not_found';

    // The factor's type is not enabled for the application; also the package
    // default's answer while no factor package is bound
    case TYPE_NOT_ENABLED = 'type_not_enabled';

    // The identity has no factor to send a code for
    case NO_FACTOR = 'no_factor';

    // The identity is not active
    case IDENTITY_INACTIVE = 'identity_inactive';

    // The identity is a machine identity, which has no further factors
    case MACHINE_IDENTITY = 'machine_identity';

    // The factor package's own cap on sending codes has been reached
    case SENDING_CAPPED = 'sending_capped';

    // The factor package does not accept the code's outcome
    case NOT_ACCEPTED = 'not_accepted';
}
