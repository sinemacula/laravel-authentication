<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * What a proof was made for, part of its binding: a sign-in, a reauthentication
 * on an active session, a step-up, or the confirmation of a factor enrolled
 * while a pending session waits for one. A proof made for one is never accepted
 * for another, except that a pending session takes an enrolment's confirming
 * factor as the further factor it waits for.
 *
 * The values follow the further-factor package's purposes, spelt with this
 * package's identifiers (`enrollment`), so the integration between them maps
 * one onto the other by case, not by value.
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

    // The confirmation of a factor enrolled while a pending session waits for a
    // further factor and the identity has none
    case ENROLLMENT = 'enrollment';
}
