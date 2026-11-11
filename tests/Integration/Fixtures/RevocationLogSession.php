<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Session model revoked while a `session_revocations` row names it and ending
 * when a `session_ends` row says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RevocationLogSession extends Session
{
    /**
     * Return when a `session_revocations` row revoked the session, falling back
     * to the session's own column.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        $logged = $this->getConnection()
            ->table('session_revocations')
            ->where('session_id', $this->getKey())
            ->value('revoked_at');

        return $logged === null ? parent::getRevokedAt() : $this->asDateTime($logged);
    }

    /**
     * Return when a `session_ends` row ended the session, falling back to the
     * session's own absolute deadline.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        $ended = $this->getConnection()
            ->table('session_ends')
            ->where('session_id', $this->getKey())
            ->value('ended_at');

        return $ended === null ? parent::getAbsoluteExpiresAt() : $this->asDateTime($ended);
    }
}
