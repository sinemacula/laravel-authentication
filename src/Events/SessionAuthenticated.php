<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a session is bound to a guard during authentication, after
 * `PrincipalAssigned`. The context's session is never `null`; the package's own
 * listener records the session's last use from it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionAuthenticated extends ContextEvent {}
