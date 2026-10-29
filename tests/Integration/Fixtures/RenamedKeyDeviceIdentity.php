<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity whose devices are `RenamedKeyDevice` rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RenamedKeyDeviceIdentity extends StubPrincipal
{
    /**
     * The identity's devices, keyed by `device_uuid`.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return $this->morphMany(RenamedKeyDevice::class, 'authenticatable');
    }
}
