<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * The kind of subject an access token's `sub` names, carried in `sub_type`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SubjectType: string
{
    case PERSON  = 'person';
    case MACHINE = 'machine';
}
