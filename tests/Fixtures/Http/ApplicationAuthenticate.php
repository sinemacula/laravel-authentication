<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Auth\Middleware\Authenticate;

/**
 * An application's own `auth` middleware, extending Laravel's rather than the
 * package's, so a guest on a package guard is refused by Laravel's middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationAuthenticate extends Authenticate {}
