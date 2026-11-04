<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors\Enums;

/**
 * A change the factor package made to an identity's factors, once it is made,
 * for which it judges the session the change was made from again
 * (`SessionService::factorChanged()`). The factor-change gate's `FactorChange`
 * names a change before it is made, by the freshness operation it must be fresh
 * for; this names it after, for the judgement. The case decides only the reason
 * a revocation of the session records: `factor_removed` for a removal,
 * `factor_changed` for every other change.
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

    // A factor removed, a passkey's included, once factorRemoved() has voided
    // its proofs and ended the identity's other sessions; never in its place
    case FACTOR_REMOVED = 'factor_removed';

    // Any other change to the identity's factors that may leave the session
    // short of what it is asked
    case OTHER = 'other';
}
