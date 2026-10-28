<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\UserProvider;

/**
 * Identity provider contract.
 *
 * Marker extension of Laravel's `UserProvider` so the package can type-hint
 * against an `IdentityProvider` while remaining a drop-in replacement for any
 * framework user provider.
 *
 * The JWT guard resolves bearer identities with `retrieveById()` and the `sub`
 * claim, and on refresh reloads the device's owner with `retrieveById()` and
 * the owner key stored on the device row, so the provider's scoping applies to
 * both.
 *
 * Identity lookups decide authentication, so an implementation must read from
 * the write connection, never a read replica that can lag behind a deactivation
 * or deletion (see `Database\WriteConnection`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityProvider extends UserProvider {}
