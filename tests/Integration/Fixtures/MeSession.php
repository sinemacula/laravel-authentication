<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Session fixture for the `me` route binding: the shipped session model with
 * the trait, as an application extends it, and soft deletes, so a binding that
 * allows trashed models can be shown to reach one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MeSession extends Session
{
    use ResolvesMeRouteBinding, SoftDeletes;
}
