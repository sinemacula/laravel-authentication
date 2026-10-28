<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity on the default connection whose devices are `UnreachableDevice`
 * rows, so the bearer `did` lookup fails while connecting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnreachableDeviceIdentity extends StubPrincipal
{
    /**
     * The identity's devices on the unreachable connection.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return UnreachableDevice::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
