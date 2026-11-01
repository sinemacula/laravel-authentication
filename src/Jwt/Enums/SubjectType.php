<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt\Enums;

/**
 * The kind of subject an access token's `sub` names, carried in `sub_type`: a
 * person (a human identity, signed in on a session or in access-only mode) or a
 * machine (the non-human identity an API key belongs to, holding a client
 * credentials token). The two never overlap, so one kind's token can never be
 * read as the other's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SubjectType: string
{
    case PERSON  = 'person';
    case MACHINE = 'machine';
}
