<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * What a proof was made for, part of its binding: a sign-in, a reauthentication
 * on an active session, or a step-up. A proof made for one is never accepted
 * for another.
 *
 * The values are the further-factor package's own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Purpose: string
{
    // A sign-in, the first factor or a further factor it waits for
    case SIGN_IN = 'sign_in';

    // A reauthentication on an active session
    case REAUTHENTICATE = 'reauthenticate';

    // A step-up on an active session
    case STEP_UP = 'step_up';
}
