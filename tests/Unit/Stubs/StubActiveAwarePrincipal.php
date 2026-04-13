<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

/**
 * Stub principal that implements the `CanBeActive` contract,
 * extending the base `StubPrincipal` Eloquent model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubActiveAwarePrincipal extends StubPrincipal implements CanBeActive {}
