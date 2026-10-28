<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when an identity registers a passkey, once the new row is
 * committed on the passkey's own connection (never for one that is rolled
 * back).
 *
 * The context carries the guard the passkey was registered through, the client
 * that registered it, the identity that owns it, the method `passkey`, and the
 * passkey's id in `credentialId`. Never carries the credential id, the public
 * key or the user handle.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyAdded extends ContextEvent {}
