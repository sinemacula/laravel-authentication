<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Auth\EloquentUserProvider;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;

/**
 * Laravel's Eloquent user provider offered as an identity provider, whose
 * rehash saves the model with its events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EloquentIdentityProvider extends EloquentUserProvider implements IdentityProvider {}
