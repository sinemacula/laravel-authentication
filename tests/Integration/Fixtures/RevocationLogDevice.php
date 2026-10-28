<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model that derives its revocation from another table: it is revoked
 * while a row in `device_revocations` names it, as an application might record
 * revocations outside the device row.
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
}
