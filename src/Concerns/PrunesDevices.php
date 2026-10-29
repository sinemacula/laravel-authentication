<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use SineMacula\Laravel\Authentication\Database\DeviceRetention;

/**
 * Lets Laravel's `model:prune` delete devices whose session is over: revoked,
 * or past its idle or absolute deadline, longer ago than the retention in
 * `authentication.device.prune_after_days`.
 *
 * Retention is counted from the time the session ended (the revocation or the
 * deadline), never from when the device was created, so a device is kept for
 * audit for the same time however long its session lasted. A pruned device's
 * tokens fail as an unknown device, just as they already fail once it is
 * revoked or ended, so retention changes nothing about authentication.
 *
 * The trait composes `MassPrunable` and replaces its `prunable()`, so a model
 * opts in with this trait alone: using `MassPrunable` beside it would be a
 * collision of the two `prunable()` methods. Columns come from the
 * `EloquentDevice` name accessors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\EloquentDevice
 */
trait PrunesDevices
{
    use MassPrunable;

    /**
     * The devices revoked, or past either deadline, at or before the cutoff:
     * now less the configured retention. Every device time is a whole second,
     * so a deadline is pruned from the second it names.
     *
     * @return \Illuminate\Database\Eloquent\Builder<static>
     *
     * @throws \InvalidArgumentException
     */
    public function prunable(): Builder
    {
        $cutoff = $this->fromDateTime(CarbonImmutable::now()->subDays(DeviceRetention::days()));

        return $this->newQuery()->where(function (Builder $query) use ($cutoff): void {
            $query->where($this->getRevokedAtName(), '<=', $cutoff)
                ->orWhere($this->getIdleExpiresAtName(), '<=', $cutoff)
                ->orWhere($this->getAbsoluteExpiresAtName(), '<=', $cutoff);
        });
    }
}
