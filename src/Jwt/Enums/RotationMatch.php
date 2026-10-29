<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * Which of a live device's refresh credentials a presented rotation id is, when
 * it is one of them: the current one, or the one it replaced presented inside
 * the grace window, which gets the current credential without a rotation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum RotationMatch
{
    case CURRENT;
    case PREVIOUS;
}
