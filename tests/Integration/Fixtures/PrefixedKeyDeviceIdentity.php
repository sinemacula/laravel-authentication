<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity whose devices are `PrefixedKeyDevice` rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrefixedKeyDeviceIdentity extends StubPrincipal
{
    /**
     * The identity's devices keyed by `dev_` strings.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return PrefixedKeyDevice::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
