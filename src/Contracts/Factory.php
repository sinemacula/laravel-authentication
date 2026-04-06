<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Factory as IlluminateFactory;

/**
 * Auth manager factory contract.
 *
 * Marker extension of Laravel's `Factory` so the package's
 * `AuthManager` may be type-hinted as a package factory in tests
 * and consumer code.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface Factory extends IlluminateFactory {}
