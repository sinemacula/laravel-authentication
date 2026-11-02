<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * The actions a pending credential may be used for, each with a stable name: a
 * pending session allows only those of its first outstanding requirement, and
 * nothing because of a route's purpose.
 *
 * The `mfa.*` names follow the further-factor package's actions, spelt with
 * this package's identifiers (`enrollment`), so the two bootstrap actions'
 * values differ from that package's and the integration between them maps one
 * onto the other by case, not by value; listing and choosing principals are
 * this package's own.
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

    // Confirm that enrolment, receiving its secrets and any recovery codes
    case CONFIRM_BOOTSTRAP_ENROLLMENT = 'mfa.confirm_bootstrap_enrollment';

    // List the principals the identity may choose from
    case LIST_PRINCIPALS = 'list_principals';

    // Choose the principal the session acts as
    case CHOOSE_PRINCIPAL = 'choose_principal';
}
