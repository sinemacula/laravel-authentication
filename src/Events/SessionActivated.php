<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a session that returned to pending activates again, every
 * requirement it waited on met: it holds a new token pair, and no token from
 * before its return is accepted. A sign-in's first activation is a sign-in,
 * reported by `SessionCreated` and `SignedIn` instead.
 *
 * Dispatched once the activation is committed on the session's own connection,
 * never for one that is rolled back. The context carries the guard, the client,
 * the identity, principal, active tenant, session and the method it records.
 * Never carries a credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionActivated extends ContextEvent {}
