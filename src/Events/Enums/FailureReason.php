<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable reason a sign-in, a request's access token, a refresh or a
 * principal switch failed, carried on the `AuthenticationFailed` event and on a
 * failed `SignInResult`.
 *
 * Backed, so SIEM consumers count failure modes without scraping log messages.
 * `account_rate_limited` is the one reason a sign-in's result never carries: a
 * refusal by the account's own limit is answered as `invalid_credentials`, so
 * it does not reveal that the account exists, and only the server-side event
 * says why.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureReason: string
{
    // The sign-in method did not accept the input
    case INVALID_CREDENTIALS = 'invalid_credentials';

    // The guard does not allow the sign-in method, or no longer allows the
    // method that started the device's session (or the device records none)
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The identifier, the device or the IP address has used up its attempts for
    // now
    case RATE_LIMITED = 'rate_limited';

    // The account the identifier found has used up its attempts for now; only
    // on the event, while the sign-in's result says invalid_credentials
    case ACCOUNT_RATE_LIMITED = 'account_rate_limited';

    // The guard's identity provider does not return the identity, or not the
    // device's exact owner
    case IDENTITY_UNKNOWN = 'identity_unknown';

    // The identity's `isActive()` returned false
    case IDENTITY_INACTIVE = 'identity_inactive';

    // No principal could be resolved for the identity
    case PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    // The principal named (pinned, or a token's pid) does not resolve to that
    // exact principal of the identity
    case PRINCIPAL_MISMATCH = 'principal_mismatch';

    // The principal reported inactive
    case PRINCIPAL_INACTIVE = 'principal_inactive';

    // The tenant the principal acts within reported inactive, or opts into
    // activation and cannot be loaded
    case TENANT_INACTIVE = 'tenant_inactive';

    // The guard's audience policy does not admit the identity as the principal
    case PRINCIPAL_INELIGIBLE = 'principal_ineligible';

    // The guard requires the identifier the sign-in used to be verified, and it
    // is not
    case IDENTIFIER_UNVERIFIED = 'identifier_unverified';

    // The pinned device is not one of the identity's live devices
    case DEVICE_MISMATCH = 'device_mismatch';

    // A further factor is required, which only signIn() can ask for
    case ADDITIONAL_FACTOR_REQUIRED = 'additional_factor_required';

    // The further factor of a pending sign-in was not verified, and the pending
    // sign-in was discarded
    case ADDITIONAL_FACTOR_FAILED = 'additional_factor_failed';

    // A pending choice of principal was discarded without a choice
    case PRINCIPAL_CHOICE_ABANDONED = 'principal_choice_abandoned';

    // The pending sign-in is unknown, expired, already used, or not for this
    // guard
    case PENDING_INVALID = 'pending_invalid';

    // The token does not decode, has expired, lacks a claim its type needs, or
    // is of another type, guard, issuer or audience
    case TOKEN_INVALID = 'token_invalid';

    // A token issued without a device was issued at or before the identity's or
    // the principal's "tokens valid after" time
    case ISSUED_BEFORE_CUTOFF = 'issued_before_cutoff';

    // The device id is not a key of the device model, or names no device
    case DEVICE_UNKNOWN = 'device_unknown';

    // The device belongs to another guard's sessions, or to none; not revoked
    case DEVICE_GUARD_MISMATCH = 'device_guard_mismatch';

    // The device is marked revoked
    case DEVICE_REVOKED = 'device_revoked';

    // The device's idle or absolute deadline is reached, or missing
    case SESSION_EXPIRED = 'session_expired';

    // The token was issued for a principal the device no longer acts as
    case DEVICE_PRINCIPAL_MISMATCH = 'device_principal_mismatch';

    // A rotated refresh token was presented: neither the current rotation id
    // nor the previous one inside the grace window; the device is revoked
    case ROTATION_REUSE = 'rotation_reuse';

    // The device's security state changed while the token was being rotated and
    // the token is still the current one; the client may retry
    case ROTATION_CONFLICT = 'rotation_conflict';

    // The device holds no refresh credential, so a replay cannot be told
    // apart; not revoked
    case REFRESH_KEY_MISSING = 'refresh_key_missing';

    // More than one source the guard reads a refresh token from carries one
    case REFRESH_TOKEN_CONFLICT = 'refresh_token_conflict';

    // A refresh token in the cookie came without an allowed origin or the
    // custom header
    case CROSS_SITE_REQUEST = 'cross_site_request';

    /**
     * Whether a sign-in method may answer with this reason. Every other reason
     * is the session service's to decide, so a method that returns one is
     * misconfigured.
     *
     * @return bool
     */
    public function isSignInMethodReason(): bool
    {
        return $this === self::INVALID_CREDENTIALS;
    }
}
