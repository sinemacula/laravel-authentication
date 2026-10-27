<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable reason a sign-in failed, carried on the `SignInFailed` event
 * and on a failed `SignInResult`. `account_rate_limited` is the one reason the
 * result never carries: a refusal by the account's own limit is answered as
 * `invalid_credentials`, so it does not reveal that the account exists, and
 * only the server-side event says why.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SignInFailureReason: string
{
    // The sign-in method did not accept the input
    case INVALID_CREDENTIALS = 'invalid_credentials';

    // The guard does not allow the sign-in method
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The identifier or the IP address has used up its attempts for now
    case RATE_LIMITED = 'rate_limited';

    // The account the identifier found has used up its attempts for now; only
    // on SignInFailed, while the result says invalid_credentials
    case ACCOUNT_RATE_LIMITED = 'account_rate_limited';

    // The guard's identity provider does not return the identity
    case IDENTITY_UNKNOWN = 'identity_unknown';

    // The identity reported inactive
    case IDENTITY_INACTIVE = 'identity_inactive';

    // No principal could be resolved for the identity
    case PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    // The requested principal does not belong to the identity
    case PRINCIPAL_MISMATCH = 'principal_mismatch';

    // The requested device is not one of the identity's live devices
    case DEVICE_MISMATCH = 'device_mismatch';

    // The principal reported inactive
    case PRINCIPAL_INACTIVE = 'principal_inactive';

    // The tenant the principal acts within reported inactive, or opts into
    // activation and cannot be loaded
    case TENANT_INACTIVE = 'tenant_inactive';

    // The guard does not accept principals of the principal's type
    case PRINCIPAL_INELIGIBLE = 'principal_ineligible';

    // The guard requires the identifier the sign-in used to be verified, and it
    // is not
    case IDENTIFIER_UNVERIFIED = 'identifier_unverified';

    // A further factor is required, which only signIn() can ask for
    case ADDITIONAL_FACTOR_REQUIRED = 'additional_factor_required';

    // The further factor of a pending sign-in was not verified, and the pending
    // sign-in was discarded
    case ADDITIONAL_FACTOR_FAILED = 'additional_factor_failed';

    // The pending sign-in is unknown, expired, already used, or not for this
    // guard
    case PENDING_INVALID = 'pending_invalid';
}
