<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\HasOne;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model that derives its revocation from a `DeviceRevocation` relation
 * it always eager-loads (`$with`), so the revocation arrives with the lookup
 * that finds the device rather than from a read of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EagerRevocationLogDevice extends Device
{
    /** @var list<string> The relations to eager load on every query. */
    protected $with = ['revocation'];

    /**
     * Return when the eager-loaded revocation revoked the device, falling back
     * to the device's own column.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        $revocation = $this->getRelationValue('revocation');

        return $revocation instanceof DeviceRevocation ? $revocation->revoked_at : parent::getRevokedAt();
    }

    /**
     * The recorded revocation of the device, if any.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasOne<\Tests\Integration\Fixtures\DeviceRevocation, $this>
     */
    public function revocation(): HasOne
    {
        return $this->hasOne(DeviceRevocation::class, 'device_id');
    }
}
