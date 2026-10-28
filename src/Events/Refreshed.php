<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched after a successful refresh-token exchange, once the rotation is
 * committed on the device's own connection: at once when that connection has no
 * open transaction, after its transaction commits otherwise, and never for a
 * refresh that is rolled back. A transaction on another connection neither
 * delays nor cancels it.
 *
 * The context carries the guard, the client, the identity, principal and tenant
 * bound on the refreshed guard, the device whose rotation id was rotated, and
 * the method its session records, so activity-log consumers can attribute the
 * refresh without a second round trip through the guard.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Refreshed extends ContextEvent {}
