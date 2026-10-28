<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Why a device was revoked, stored on the device row and carried on the
 * `DeviceRevoked` event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationReason: string
{
    // A refresh token was presented whose rotation id is neither the device's
    // current one nor the previous one inside the grace window
    case ROTATION_REUSE = 'rotation_reuse';

    // The device's own session signed out
    case SIGNED_OUT = 'signed_out';

    // The identity or principal signed out of every session
    case SIGNED_OUT_EVERYWHERE = 'signed_out_everywhere';

    // The application revoked the device (from a list of devices, an
    // administrator)
    case REVOKED = 'revoked';

    // The identity's password was changed
    case PASSWORD_CHANGED = 'password_changed';

    // The identity's password was reset
    case PASSWORD_RESET = 'password_reset';

    // A factor the identity signed in with was removed
    case FACTOR_REMOVED = 'factor_removed';

    // The identity was deactivated
    case IDENTITY_DEACTIVATED = 'identity_deactivated';

    // The principal the device's session acts as was deactivated
    case PRINCIPAL_DEACTIVATED = 'principal_deactivated';

    // The tenant the device's principal acts within was deactivated
    case TENANT_DEACTIVATED = 'tenant_deactivated';
}
