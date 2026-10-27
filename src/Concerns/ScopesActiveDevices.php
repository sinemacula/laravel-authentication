<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;

/**
 * The `ActsAsDevice` query scope `active()`: devices whose session is live,
 * neither revoked nor past its idle or absolute deadline, by the same rule the
 * device list applies, so `Device::query()->active()` and
 * `Auth::sessions()->devices()` agree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\EloquentDevice
 */
trait ScopesActiveDevices
{
    /**
     * Keep the query to devices whose session is live now: not revoked, and
     * before both its idle and its absolute deadline.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<static>  $query
     * @return void
     */
    protected function scopeActive(Builder $query): void
    {
        ActiveDevices::constrain($query, $this, CarbonImmutable::now());
    }
}
