<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * How a request for a one-time code, or a password reset link, ended. A sign-in
 * code and a reset are sent whether or not any identity has the identifier, so
 * `sent` never says that one does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CodeRequestStatus: string
{
    // A code or reset link was issued and its delivery queued
    case SENT = 'sent';

    // The identifier or the IP address has used up its requests for now, or a
    // code or link was issued for the identifier within the resend cooldown
    case RATE_LIMITED = 'rate_limited';

    // The guard does not allow the code sign-in method, or, for a reset, the
    // password method
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The input names no identifier, or one the type's normaliser rejects, or
    // the identity has no identifier of the type to verify
    case IDENTIFIER_INVALID = 'identifier_invalid';
}
