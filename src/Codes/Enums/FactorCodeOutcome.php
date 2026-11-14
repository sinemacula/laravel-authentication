<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * How checking a further factor's code, or an enrolment's, ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorCodeOutcome: string
{
    // The code matched the live challenge, which this check used up, and the
    // factor package admitted the outcome
    case VERIFIED = 'verified';

    // The code is malformed, or it did not match the live challenge of the
    // binding, which counted an attempt when the code was well formed
    case INVALID = 'invalid';

    // The challenge id is malformed or unknown, or the challenge was replaced
    // or is another binding's; no attempt is counted
    case NOT_FOUND = 'not_found';

    // The binding's own challenge was used up, by another code or by being
    // ended, whether or not it has expired since; no attempt is counted
    case USED = 'used';

    // The code is the one that used the binding's own challenge up, whether or
    // not it has expired since; no attempt is counted
    case REPLAYED = 'replayed';

    // The challenge's code has expired
    case EXPIRED = 'expired';

    // The challenge has used up its attempts
    case EXHAUSTED = 'exhausted';

    // The factor package has the factor or the identity locked
    case LOCKED = 'locked';

    // The factor package refuses, for the reason the check carries
    case REFUSED = 'refused';

    // The IP address has used up its factor code checks for now
    case RATE_LIMITED = 'rate_limited';
}
