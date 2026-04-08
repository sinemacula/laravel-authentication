<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\UserProvider;

/**
 * Identity provider contract.
 *
 * Marker extension of Laravel's `UserProvider` so the package can
 * type-hint against an `IdentityProvider` while remaining a
 * drop-in replacement for any framework user provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface IdentityProvider extends UserProvider {}
