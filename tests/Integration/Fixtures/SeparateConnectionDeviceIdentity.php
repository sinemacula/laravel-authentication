<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity on the default connection whose devices are
 * `SeparateConnectionDevice` rows on their own connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeparateConnectionDeviceIdentity extends StubPrincipal
{
    /**
     * The identity's devices, on the devices' own connection.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return $this->morphMany(SeparateConnectionDevice::class, 'authenticatable');
    }
}
