<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a device is bound to a guard during authentication, after
 * `PrincipalAssigned`. The context's device is never `null`; the package's own
 * listener records the device's last use from it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceAuthenticated extends ContextEvent {}
