<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Support\Facades\Config;

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
        $cutoff = $this->fromDateTime(CarbonImmutable::now()->subDays(self::deviceRetentionDays()));

        return $this->newQuery()->where(function (Builder $query) use ($cutoff): void {
            $query->where($this->getRevokedAtName(), '<=', $cutoff)
                ->orWhere($this->getIdleExpiresAtName(), '<=', $cutoff)
                ->orWhere($this->getAbsoluteExpiresAtName(), '<=', $cutoff);
        });
    }

    /**
     * The configured retention, in days: an integer, or a digit string as
     * `env()` returns one, from 0 to 3650.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function deviceRetentionDays(): int
    {
        $days = Config::get('authentication.device.prune_after_days', 30);

        if (is_string($days) && preg_match('/^(0|[1-9]\d{0,3})$/D', $days) === 1) {
            $days = (int) $days;
        }

        if (!is_int($days) || $days < 0 || $days > 3650) {
            throw new \InvalidArgumentException('`authentication.device.prune_after_days` must be an integer from 0 to 3650 days.');
        }

        return $days;
    }
}
