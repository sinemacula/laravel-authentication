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

    // The identity or principal signed out everywhere, or its cutoff moved
    // while a sign-in, choice or switch was in flight (`AdmissionRecheck`)
    case SIGNED_OUT_EVERYWHERE = 'signed_out_everywhere';

    // The application revoked the session
    case REVOKED = 'revoked';

    // A sign-in holding the session's refresh token replaced it with a new one
    case SUPERSEDED = 'superseded';

    // The identity's password was changed: `passwordChanged()`
    case PASSWORD_CHANGED = 'password_changed';

    // The identity's password was reset: `passwordReset()`
    case PASSWORD_RESET = 'password_reset';

    // A sign-in factor of the identity was removed: `credentialRemoved()`,
    // `factorRemoved()`, or `factorChanged()` after a removal
    case FACTOR_REMOVED = 'factor_removed';

    // The identity was deactivated: `identityDeactivated()` or
    // `AdmissionRecheck`
    case IDENTITY_DEACTIVATED = 'identity_deactivated';

    // The session's principal was deactivated: `principalDeactivated()` or
    // `AdmissionRecheck`
    case PRINCIPAL_DEACTIVATED = 'principal_deactivated';

    // The principal's tenant or the active tenant was deactivated:
    // `tenantDeactivated()`, or deactivated or deleted (`AdmissionRecheck`)
    case TENANT_DEACTIVATED = 'tenant_deactivated';

    // The identity was deleted, softly or not: `identityDeleted()` or
    // `AdmissionRecheck`
    case IDENTITY_DELETED = 'identity_deleted';

    // The session's principal was deleted, softly or not: `principalDeleted()`
    // or `AdmissionRecheck`
    case PRINCIPAL_DELETED = 'principal_deleted';

    // The active tenant's authentication policy changed and the session no
    // longer meets it: `tenantPolicyChanged()` or a refresh
    case TENANT_POLICY_CHANGED = 'tenant_policy_changed';

    // The identity established its first password: `establish()`
    case PASSWORD_ESTABLISHED = 'password_established';

    // The identity's further factors were reset: `factorReset()`
    case FACTOR_RESET = 'factor_reset';

    // A factor change that removed none left the session no longer admitted:
    // `factorChanged()`
    case FACTOR_CHANGED = 'factor_changed';

    // The session's connection was disabled: `connectionDisabled()`
    case CONNECTION_DISABLED = 'connection_disabled';

    // The session's connection was deleted: `connectionDeleted()`
    case CONNECTION_DELETED = 'connection_deleted';

    // The link the session was established through was removed: `linkRemoved()`
    case LINK_REMOVED = 'link_removed';

    // The scope of the session's link was widened: `linkScopeWidened()`
    case LINK_SCOPE_WIDENED = 'link_scope_widened';
}
