<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

/**
 * Tenant stub that opts into activation and always reports active.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubActivatableTenant extends StubTenant implements CanBeActive
{
    /**
     * Report the tenant active.
     *
     * @return bool
     */
    #[\Override]
    public function isActive(): bool
    {
        return true;
    }
}
