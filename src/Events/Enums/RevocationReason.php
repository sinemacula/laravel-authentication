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
    // A refresh token the device had already rotated was presented outside the
    // grace window
    case ROTATION_REUSE = 'rotation_reuse';
}
