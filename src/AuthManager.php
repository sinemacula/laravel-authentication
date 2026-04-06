<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use SineMacula\Laravel\Authentication\Contracts\Factory;

/**
 * Package AuthManager.
 *
 * Thin subclass of Laravel's `AuthManager` that implements the
 * package's `Factory` marker contract for IDE/typing clarity. Bound
 * to the `auth` container key by `AuthServiceProvider`. Intentionally
 * not `final` so consumers may further subclass if they need to
 * override driver resolution.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
class AuthManager extends IlluminateAuthManager implements Factory {}
