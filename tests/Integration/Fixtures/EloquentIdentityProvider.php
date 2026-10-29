<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Auth\EloquentUserProvider;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;

/**
 * Laravel's Eloquent user provider offered as an identity provider.
 *
 * Stands in for an application provider whose password rehash saves the model
 * with its events, unlike the package's model provider, so tests can prove what
 * a listener of that save does while the package's own rehash runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EloquentIdentityProvider extends EloquentUserProvider implements IdentityProvider {}
