<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable reason an authentication flow failed or a factor change was
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureReason: string
{
    // The sign-in method did not accept the input
    case INVALID_CREDENTIALS = 'invalid_credentials';

    // The application does not allow the sign-in method, or no longer allows
    // the method that started the session (or the session records none)
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The identifier, the session or the IP address has used up its attempts
    // for now
    case RATE_LIMITED = 'rate_limited';

    // The account the identifier found has used up its attempts for now; only
    // on the event, while the sign-in's result says invalid_credentials
    case ACCOUNT_RATE_LIMITED = 'account_rate_limited';

    // The guard's identity provider does not return the identity, or not the
    // session's exact owner
    case IDENTITY_UNKNOWN = 'identity_unknown';

    // The identity's `isActive()` returned false
    case IDENTITY_INACTIVE = 'identity_inactive';

    // No principal could be resolved for the identity
    case PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    // The principal named (pinned, or a token's `principal` claim) does not
    // resolve to that exact principal of the identity
    case PRINCIPAL_MISMATCH = 'principal_mismatch';

    // The principal reported inactive
    case PRINCIPAL_INACTIVE = 'principal_inactive';

    // The principal's own tenant, or the tenant the session acts in, reported
    // inactive, or opts into activation and cannot be loaded
    case TENANT_INACTIVE = 'tenant_inactive';

    // The tenant selected cannot be resolved, or the tenant access contract
    // does not let the principal act in it
    case TENANT_INELIGIBLE = 'tenant_ineligible';

    // The application access contract does not let the principal use the
    // application
    case PRINCIPAL_INELIGIBLE = 'principal_ineligible';

    // The tenant's authentication policy requires a session established through
    // one of its connections, and this one was not
    case SSO_REQUIRED = 'sso_required';

    // The guard requires the identifier the sign-in used to be verified, and it
    // is not
    case IDENTIFIER_UNVERIFIED = 'identifier_unverified';

    // The pinned session is not one of the identity's live sessions, or a
    // refresh credential proves a session other than the one expected
    case SESSION_MISMATCH = 'session_mismatch';

    // A further factor is required, which an access-only sign-in (attempt()),
    // the caller read from a refresh credential or an external reauthentication
    // (reauthenticateExternally()) cannot wait for
    case ADDITIONAL_FACTOR_REQUIRED = 'additional_factor_required';

    // The pending credential names no live pending session of this guard: it is
    // unknown, expired, revoked, already activated, or another guard's
    case PENDING_INVALID = 'pending_invalid';

    // The pending session's first outstanding requirement does not allow what
    // was asked of it (a factor while a principal is to be chosen, or a choice
    // while a factor is outstanding)
    case PENDING_ACTION_NOT_ALLOWED = 'pending_action_not_allowed';

    // The session waits on requirements, so none of its tokens is accepted
    // until it activates
    case SESSION_PENDING = 'session_pending';

    // The token does not decode, has expired, lacks a claim its type needs, or
    // is of another type, guard, issuer or audience
    case TOKEN_INVALID = 'token_invalid';

    // A sessionless token predates the identity's or principal's cutoff, or a
    // revocation moved the cutoff during a sign-in (`AdmissionRecheck`)
    case ISSUED_BEFORE_CUTOFF = 'issued_before_cutoff';

    // The session id is not a key of the session model, or names no session
    case SESSION_UNKNOWN = 'session_unknown';

    // The session belongs to another guard, or to none; not revoked
    case SESSION_GUARD_MISMATCH = 'session_guard_mismatch';

    // The session is marked revoked
    case SESSION_REVOKED = 'session_revoked';

    // The session's idle or absolute deadline is reached, or missing, or the
    // deadline a sign-in supplied had passed by the sign-in
    case SESSION_EXPIRED = 'session_expired';

    // The token was issued for a principal the session no longer acts as
    case SESSION_PRINCIPAL_MISMATCH = 'session_principal_mismatch';

    // The token names another tenant than the one the session acts in
    case SESSION_TENANT_MISMATCH = 'session_tenant_mismatch';

    // The token was issued before the session's principal or active tenant last
    // changed, or before it returned to pending or activated again
    case SESSION_SWITCHED = 'session_switched';

    // A rotated refresh token was presented: neither the current rotation id
    // nor the previous one inside the grace window; the session is revoked
    case ROTATION_REUSE = 'rotation_reuse';

    // The session's security state changed while the token was being rotated
    // and the token is still the current one; the client may retry
    case ROTATION_CONFLICT = 'rotation_conflict';

    // The session holds no refresh credential, so a replay cannot be told
    // apart; not revoked
    case REFRESH_KEY_MISSING = 'refresh_key_missing';

    // More than one carrier of a refresh token (the cookie, the body field, the
    // header) carries one, or the cookie comes twice
    case REFRESH_TOKEN_CONFLICT = 'refresh_token_conflict';

    // The refresh token came by a carrier that is not the application's
    // transport: the cookie to a body application, the body or header to a
    // cookie application
    case REFRESH_TRANSPORT_MISMATCH = 'refresh_transport_mismatch';

    // A refresh token in the cookie, or a cookie application's sign-in, start
    // or pending-session action, came without an allowed origin or the custom
    // header
    case CROSS_SITE_REQUEST = 'cross_site_request';

    // The one-time code exists but has expired; only on the event
    case CODE_EXPIRED = 'code_expired';

    // The one-time code used up its attempts and is locked until another is
    // requested; only on the event
    case CODE_EXHAUSTED = 'code_exhausted';

    // The passkey ceremony's challenge is malformed, unknown, or another
    // guard's, relying party's, purpose's, owner's or binding's
    case PASSKEY_CHALLENGE_INVALID = 'passkey_challenge_invalid';

    // The passkey ceremony's own challenge expired before it was answered
    case PASSKEY_CHALLENGE_EXPIRED = 'passkey_challenge_expired';

    // A response was submitted to the passkey ceremony's own challenge before,
    // whether or not that one authenticated
    case PASSKEY_CHALLENGE_USED = 'passkey_challenge_used';

    // The passkey's sign counter did not advance, as a cloned authenticator's
    // would not; only on the event
    case PASSKEY_COUNTER_REGRESSED = 'passkey_counter_regressed';

    // A non-human identity tried an interactive sign-in, a session, a switch, a
    // refresh or a session's token
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

    // An operation needed a fresher proof on its session, or the password given
    // to reauthenticate was wrong or not taken by the guard's freshness
    case REAUTHENTICATION_REQUIRED = 'reauthentication_required';

    // The identifier a change would set is held by another identity (found by
    // the guard's provider, or refused by the application's unique index)
    case IDENTIFIER_TAKEN = 'identifier_taken';

    // A reset, identifier change or verification link has expired; a reset
    // answers it as invalid, so only its event says so
    case LINK_EXPIRED = 'link_expired';

    // A proof handed to a pending session or a step-up is of a kind or purpose
    // the operation does not take, was not accepted by its adapter, or is timed
    // after now or before what it adds to
    case PROOF_INVALID = 'proof_invalid';

    // A proof handed to a pending session or a step-up was made by another
    // identity, on another application, or for another session
    case PROOF_BINDING_MISMATCH = 'proof_binding_mismatch';

    // A change of a further factor, or the generation of recovery codes, was
    // asked for without a fresh enough step-up on the session it was made from
    // (one made with the factor replaced or removed never counts)
    case STEP_UP_REQUIRED = 'step_up_required';

    // The destination's delivery window has had all the code deliveries it
    // allows
    case DELIVERIES_EXHAUSTED = 'deliveries_exhausted';

    // The factor package has the factor, or the identity, locked against
    // further factor codes
    case FACTOR_CODE_LOCKED = 'factor_code_locked';

    // The factor package refused to have a factor code sent or checked, or the
    // outcome of an attempt at one
    case FACTOR_CODE_REFUSED = 'factor_code_refused';

    // A change of password was asked of an identity that has none: it
    // establishes one instead
    case PASSWORD_NOT_SET = 'password_not_set';

    // A password was to be established for an identity that already has one: it
    // changes it instead
    case PASSWORD_ALREADY_SET = 'password_already_set';

    // A result an external provider verified is linked to no identity through
    // its connection, issuer and subject
    case EXTERNAL_RESULT_UNLINKED = 'external_result_unlinked';

    // The session, the link's identity or the result's link does not match the
    // external result's connection and link
    case LINK_MISMATCH = 'link_mismatch';

    /**
     * Whether a sign-in method may answer with this reason.
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
            self::PASSKEY_CHALLENGE_EXPIRED,
            self::PASSKEY_CHALLENGE_USED,
            self::PASSKEY_COUNTER_REGRESSED => true,
            default                         => false,
        };
    }

    /**
     * Whether a sign-in's result answers this reason as `invalid_credentials`,
     * so only the server-side event carries it.
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
