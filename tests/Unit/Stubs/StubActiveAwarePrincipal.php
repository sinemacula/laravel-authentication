<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

/**
 * Stub principal that implements the `CanBeActive` contract from its
 * `is_active` column, extending the base `StubPrincipal` Eloquent model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubActiveAwarePrincipal extends StubPrincipal implements CanBeActive
{
    use ProvidesActiveState;
}
