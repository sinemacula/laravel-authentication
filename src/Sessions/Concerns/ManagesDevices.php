<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;

/**
 * The session service's device management: listing an identity's active
 * devices.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ManagesDevices
{
    /**
     * One page of the identity's active devices, of every guard, for a device
     * list: most recently used first (never used last), then newest first, each
     * summarised without its digests, revocation or principal, and marked when
     * it is the device this guard is authenticated with for the request. Read
     * on the write connection through the identity's `devices()` relation.
     * `$perPage` is 1 to 100; the page is the request's `page` parameter unless
     * given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\DeviceSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function devices(Identity $identity, int $perPage = 15, ?int $page = null): LengthAwarePaginator
    {
        return ActiveDevices::page($identity, $this->guard->device(), $perPage, $page);
    }
}
