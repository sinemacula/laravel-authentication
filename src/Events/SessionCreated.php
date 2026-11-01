<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when the session service creates a session for a sign-in, which
 * every sign-in does, once the new row is committed on the session's own
 * connection (never for one that is rolled back), just before `SignedIn`, and
 * after the `SessionRevoked` (`superseded`) of the session it replaced, if any.
 *
 * The context carries the guard, the client the session was created for, the
 * identity, principal, tenant and session, and the method that created it.
 * Never carries a credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionCreated extends ContextEvent {}
