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

    // The identity or principal signed out of every session
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
    // `factorRemoved()`
    case FACTOR_REMOVED = 'factor_removed';

    // The identity was deactivated: `identityDeactivated()`
    case IDENTITY_DEACTIVATED = 'identity_deactivated';

    // The principal the session acts as was deactivated:
    // `principalDeactivated()`
    case PRINCIPAL_DEACTIVATED = 'principal_deactivated';

    // The tenant was deactivated: a session acting as one of its principals, or
    // acting in it: `tenantDeactivated()`
    case TENANT_DEACTIVATED = 'tenant_deactivated';

    // The authentication policy of the tenant the session is active in changed
    // and the session no longer meets it: `tenantPolicyChanged()`, or a refresh
    // that finds it must be established through a connection it was not
    case TENANT_POLICY_CHANGED = 'tenant_policy_changed';

    // The identity established its first password: `passwordEstablished()`
    case PASSWORD_ESTABLISHED = 'password_established';

    // The identity's further factors were reset: `factorReset()`
    case FACTOR_RESET = 'factor_reset';
}
