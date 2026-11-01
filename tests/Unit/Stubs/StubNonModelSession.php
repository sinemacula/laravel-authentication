<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * A session class that declares the Eloquent session contract without being an
 * Eloquent model, so the persistence the contract promises cannot happen.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class StubNonModelSession implements EloquentSession {}
