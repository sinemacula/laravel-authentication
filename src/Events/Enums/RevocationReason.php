<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Why a session was revoked, stored on the session row and carried on the
 * `SessionRevoked` event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationReason: string
{
    // A refresh token was presented whose rotation id is neither the session's
    // current one nor the previous one inside the grace window
    case ROTATION_REUSE = 'rotation_reuse';

    // The session signed itself out
    case SIGNED_OUT = 'signed_out';

    // The identity or principal signed out of every session; or a sign-in,
    // choice or switch whose identity's or principal's "tokens valid after"
    // cutoff a revocation moved while it was in flight (`AdmissionRecheck`)
    case SIGNED_OUT_EVERYWHERE = 'signed_out_everywhere';

    // The application revoked the session (from a list of sessions, an
    // administrator)
    case REVOKED = 'revoked';

    // A sign-in that proved, with the session's refresh token, that it holds
    // the session replaced it with a new one
    case SUPERSEDED = 'superseded';

    // The identity's password was changed: `passwordChanged()`
    case PASSWORD_CHANGED = 'password_changed';

    // The identity's password was reset: `passwordReset()`
    case PASSWORD_RESET = 'password_reset';

    // A sign-in factor of the identity was removed: a first-factor credential,
    // `credentialRemoved()`, or one of the factor package's factors,
    // `factorRemoved()`, and `factorChanged()` judging the current session
    // again after that removal
    case FACTOR_REMOVED = 'factor_removed';

    // The identity was deactivated: `identityDeactivated()`; or a sign-in whose
    // identity was deactivated meanwhile (`AdmissionRecheck`)
    case IDENTITY_DEACTIVATED = 'identity_deactivated';

    // The principal the session acts as was deactivated:
    // `principalDeactivated()`; or a sign-in, choice or switch whose principal
    // was deactivated meanwhile (`AdmissionRecheck`)
    case PRINCIPAL_DEACTIVATED = 'principal_deactivated';

    // The tenant was deactivated: a session acting as one of its principals, or
    // acting in it: `tenantDeactivated()`; or a sign-in, choice or switch whose
    // principal's own tenant or active tenant was deactivated or deleted
    // meanwhile (`AdmissionRecheck`)
    case TENANT_DEACTIVATED = 'tenant_deactivated';

    // The identity was deleted, a soft delete included: `identityDeleted()`; or
    // a sign-in whose identity was deleted meanwhile (`AdmissionRecheck`)
    case IDENTITY_DELETED = 'identity_deleted';

    // The principal the session acts as was deleted, a soft delete included:
    // `principalDeleted()`; or a sign-in, choice or switch whose principal was
    // deleted meanwhile (`AdmissionRecheck`)
    case PRINCIPAL_DELETED = 'principal_deleted';

    // The authentication policy of the tenant the session is active in changed
    // and the session no longer meets it: `tenantPolicyChanged()`, or a refresh
    // that finds it must be established through a connection it was not
    case TENANT_POLICY_CHANGED = 'tenant_policy_changed';

    // The identity established its first password: `passwordEstablished()`
    case PASSWORD_ESTABLISHED = 'password_established';

    // The identity's further factors were reset: `factorReset()`
    case FACTOR_RESET = 'factor_reset';

    // An addition to the factor package's factors, a change that removes none,
    // left the current session no longer admitted: `factorChanged()`
    case FACTOR_CHANGED = 'factor_changed';

    // The connection the session was established through was disabled:
    // `connectionDisabled()`
    case CONNECTION_DISABLED = 'connection_disabled';

    // The connection the session was established through was deleted:
    // `connectionDeleted()`
    case CONNECTION_DELETED = 'connection_deleted';

    // The link the session was established through was removed: `linkRemoved()`
    case LINK_REMOVED = 'link_removed';

    // The scope of the link the session was established through was widened, so
    // the link may now act for more than the session was established for:
    // `linkScopeWidened()`
    case LINK_SCOPE_WIDENED = 'link_scope_widened';
}
