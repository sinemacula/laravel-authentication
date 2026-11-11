<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors\Enums;

/**
 * A change the factor package made to an identity's factors, for which it
 * judges the session again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChangeMade: string
{
    // A further factor added to the identity from an active session, its
    // enrolment confirmed
    case FACTOR_CONFIRMED = 'factor_confirmed';

    // A passkey registered and associated as a factor, from the passkey factor
    // gate's registering()
    case PASSKEY_FACTOR_REGISTERED = 'passkey_factor_registered';

    // A factor removed, a passkey's included, for a factor package that hands
    // every change to this judgement, after factorRemoved()
    case FACTOR_REMOVED = 'factor_removed';

    // Any other change to the identity's factors that removes none of them and
    // may leave the session short of what it is asked, a new set of recovery
    // codes included when the factor policy can change with it
    case OTHER = 'other';
}
