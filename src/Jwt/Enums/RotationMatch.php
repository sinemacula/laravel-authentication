<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * Which of a live device's refresh credentials a presented rotation id is, when
 * it is one of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum RotationMatch
{
    // The current rotation id: the exchange rotates it
    case CURRENT;

    // The rotation id the current one replaced, inside the grace window: the
    // exchange hands back the current credential without rotating
    case PREVIOUS;
}
