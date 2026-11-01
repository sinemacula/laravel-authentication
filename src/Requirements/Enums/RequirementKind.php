<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements\Enums;

/**
 * The parts a requirement on a session's authentication may have, in the order
 * a requirement lists them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RequirementKind: string
{
    // A further factor beyond the first, of any kind
    case ADDITIONAL_VERIFICATION = 'additional_verification';

    // Authentication its verifier judged to be multifactor
    case MULTIFACTOR = 'multifactor';

    // Authentication at or above an assurance level
    case MINIMUM_LEVEL = 'minimum_level';

    // An authenticator that resists phishing
    case PHISHING_RESISTANCE = 'phishing_resistance';
}
