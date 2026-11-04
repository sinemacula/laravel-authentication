<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * What judging the current session again after a change of the factor package's
 * did to it (`SessionService::factorChanged()`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChangeStatus: string
{
    // Judged again and still meeting what it is asked: it stays active
    case ACTIVE = 'active';

    // Returned to pending by this call: the result carries the pending session
    // and its new pending credential, and its tokens stop from the commit
    case PENDING = 'pending';

    // Revoked by this call
    case REVOKED = 'revoked';

    // Neither kept, returned to pending nor revoked by this call: it was no
    // longer the session given or no longer live and active when locked, or
    // another writer revoked it meanwhile; says nothing of whether it is usable
    case SKIPPED = 'skipped';
}
