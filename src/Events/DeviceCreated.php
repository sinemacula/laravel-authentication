<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when the session service creates a device for a sign-in, once the
 * new row is committed on the device's own connection (never for one that is
 * rolled back), just before `SignedIn`. A sign-in that continues an existing
 * device of the same client does not dispatch it.
 *
 * The context carries the guard, the client the device was created for, the
 * identity, principal, tenant and device, and the method that created it. Never
 * carries a credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceCreated extends ContextEvent {}
