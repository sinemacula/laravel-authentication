<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * Which of a live session's refresh credentials a presented rotation id
 * matched: the current one, or the previous one inside the grace window.
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
