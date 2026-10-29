<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable reason a sign-in, a request's access token or API key, a
 * refresh, a principal switch, a code request, a client credentials exchange, a
 * password reset or an identifier change failed, carried on the
 * `AuthenticationFailed` event and on a failed `SignInResult`.
 *
 * Backed, so SIEM consumers count failure modes without scraping log messages.
 * The concealed reasons (`isConcealed()`) are ones a sign-in's result never
 * carries: a refusal by the account's own limit, an expired or exhausted code
 * and a passkey whose sign counter did not advance are answered as
 * `invalid_credentials`, so the result does not reveal that the account or a
 * code exists, and only the server-side event says why; an expired reset link
 * is answered as an invalid one in the same way.
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

    // The one-time code exists but has expired; only on the event
    case CODE_EXPIRED = 'code_expired';

    // The one-time code used up its attempts and is locked until another is
    // requested; only on the event
    case CODE_EXHAUSTED = 'code_exhausted';

    // The passkey ceremony's challenge is unknown, expired, already used, or
    // another guard's or purpose's
    case PASSKEY_CHALLENGE_INVALID = 'passkey_challenge_invalid';

    // The passkey's sign counter did not advance, as a cloned authenticator's
    // would not; only on the event
    case PASSKEY_COUNTER_REGRESSED = 'passkey_counter_regressed';

    // A non-human identity tried an interactive sign-in, a session, a switch, a
    // refresh or a device's token
    case MACHINE_IDENTITY = 'machine_identity';

    // The API key or client credential is malformed, unknown, has the wrong
    // secret, or is not a non-human identity's
    case CREDENTIAL_INVALID = 'credential_invalid';

    // The API key or client credential is revoked
    case CREDENTIAL_REVOKED = 'credential_revoked';

    // The API key or client credential has expired, including a rotated key
    // once its overlap ended
    case CREDENTIAL_EXPIRED = 'credential_expired';

    // The API key or client credential was issued for another guard
    case CREDENTIAL_GUARD_MISMATCH = 'credential_guard_mismatch';

    // A requested scope is malformed or not granted to the credential
    case SCOPE_INVALID = 'scope_invalid';

    // A change of identifier was asked for without a recent sign-in,
    // reauthentication or confirmed further factor, or the password given to
    // reauthenticate was wrong
    case REAUTHENTICATION_REQUIRED = 'reauthentication_required';

    // The identifier a change would set is held by another identity (found by
    // the guard's provider, or refused by the application's unique index)
    case IDENTIFIER_TAKEN = 'identifier_taken';

    // The reset or change link's token exists but has expired; only on the
    // event
    case LINK_EXPIRED = 'link_expired';

    /**
     * Whether a sign-in method may answer with this reason. Every other reason
     * is the session service's to decide, so a method that returns one is
     * misconfigured. `identifier_unverified` is a method's answer only once the
     * input proved possession of the identifier, as a correct one-time code
     * does.
     *
     * @return bool
     */
    public function isSignInMethodReason(): bool
    {
        return match ($this) {
            self::INVALID_CREDENTIALS,
            self::IDENTIFIER_UNVERIFIED,
            self::CODE_EXPIRED,
            self::CODE_EXHAUSTED,
            self::PASSKEY_CHALLENGE_INVALID,
            self::PASSKEY_COUNTER_REGRESSED => true,
            default                         => false,
        };
    }

    /**
     * Whether only the server-side event may carry this reason: a sign-in's
     * result answers it as `invalid_credentials`, with no wait, so it reveals
     * neither that an account exists nor that a code was requested for it.
     *
     * @return bool
     */
    public function isConcealed(): bool
    {
        return match ($this) {
            self::ACCOUNT_RATE_LIMITED,
            self::CODE_EXPIRED,
            self::CODE_EXHAUSTED,
            self::LINK_EXPIRED,
            self::PASSKEY_COUNTER_REGRESSED => true,
            default                         => false,
        };
    }
}
