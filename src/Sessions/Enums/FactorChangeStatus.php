<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * What judging the current session again after a factor change did to it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChangeStatus: string
{
    // Still meets what it is asked and stays active
    case ACTIVE = 'active';

    // Returned to pending by this call
    case PENDING = 'pending';

    // Revoked by this call
    case REVOKED = 'revoked';

    // Left alone: no longer the session given, or no longer live and active
    case SKIPPED = 'skipped';
}
