<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * The actions a pending credential may be used for.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PendingAction: string
{
    // List the identity's factors
    case LIST_FACTORS = 'mfa.list_factors';

    // Send, or send again, a code for a factor
    case SEND_CODE = 'mfa.send_code';

    // Verify a factor or a recovery code
    case VERIFY = 'mfa.verify';

    // Start enrolling a factor when one is required and the identity has none
    case START_BOOTSTRAP_ENROLLMENT = 'mfa.start_bootstrap_enrollment';

    // Confirm that enrolment
    case CONFIRM_BOOTSTRAP_ENROLLMENT = 'mfa.confirm_bootstrap_enrollment';

    // List the principals the identity may choose from
    case LIST_PRINCIPALS = 'list_principals';

    // Choose the principal the session acts as
    case CHOOSE_PRINCIPAL = 'choose_principal';
}
