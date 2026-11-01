<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a session's identity proves its first factor again, once the
 * reauthentication's proof is committed on the session's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a reauthentication that is rolled back.
 *
 * The context carries the guard, the client, the identity, principal and tenant
 * the reauthentication admitted, the session (whose authentication time it
 * renewed, and nothing else) and the method the identity reauthenticated with.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Reauthenticated extends ContextEvent {}
