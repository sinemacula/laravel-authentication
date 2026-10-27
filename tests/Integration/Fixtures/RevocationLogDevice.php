<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model that derives its revocation and the end of its session from
 * other tables: it is revoked while a row in `device_revocations` names it, and
 * its session ends at the time a row in `device_session_ends` gives it, as an
 * application might record either outside the device row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RevocationLogDevice extends Device
{
    /**
     * Return when a `device_revocations` row revoked the device, falling back
     * to the device's own column.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        $logged = $this->getConnection()
            ->table('device_revocations')
            ->where('device_id', $this->getKey())
            ->value('revoked_at');

        return $logged === null ? parent::getRevokedAt() : $this->asDateTime($logged);
    }

    /**
     * Return when a `device_session_ends` row ended the session, falling back
     * to the device's own absolute deadline.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        $ended = $this->getConnection()
            ->table('device_session_ends')
            ->where('device_id', $this->getKey())
            ->value('ended_at');

        return $ended === null ? parent::getAbsoluteExpiresAt() : $this->asDateTime($ended);
    }
}
