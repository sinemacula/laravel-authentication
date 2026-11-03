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

    // The code or the challenge id is malformed, no live challenge was issued
    // for the binding, it was used up or replaced, its transaction is another,
    // or the code did not match
    case INVALID = 'invalid';

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
