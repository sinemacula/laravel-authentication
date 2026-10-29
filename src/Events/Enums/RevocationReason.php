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
}
