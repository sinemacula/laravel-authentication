<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * What the factor package answered when asked whether a factor code may be sent
 * or checked: it may; the factor or the identity is locked, until a time it
 * names; or it refuses, for a reason it names.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorCodeStanding: string
{
    // The code may be sent or checked
    case ADMITTED = 'admitted';

    // The factor or the identity is locked out
    case LOCKED = 'locked';

    // The factor package refuses, for the reason it gives
    case REFUSED = 'refused';
}
