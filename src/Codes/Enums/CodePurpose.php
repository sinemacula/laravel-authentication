<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * What a one-time code challenge was issued for, part of its key so a challenge
 * never serves another purpose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CodePurpose: string
{
    // A sign-in with a code method (`phone_code`, `email_code`)
    case SIGN_IN = 'sign_in';

    // Verifying an identity's current identifier of a type
    case VERIFICATION = 'verification';

    // A further factor's code, for a sign-in or a step-up, sent through the
    // factor package's seam
    case MFA = 'mfa';

    // The confirmation of a factor being enrolled, bound to the pending factor
    // and its enrolment grant
    case ENROLLMENT = 'enrollment';

    // A password reset code for an identifier
    case PASSWORD_RESET = 'password_reset';

    // A password reset link's token for an identifier
    case PASSWORD_RESET_LINK = 'password_reset_link';

    // Proving the new identifier of one change request
    case CHANGE_IDENTIFIER = 'change_identifier';
}
