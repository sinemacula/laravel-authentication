<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a passkey's assertion is verified, by a sign-in or as a
 * further factor, once its new sign count and last use are committed on the
 * passkey's own connection (never for a use that is rolled back). A sign-in
 * dispatches it whether or not the session is then admitted: the passkey was
 * used.
 *
 * The context carries the guard, the client that used the passkey, the identity
 * that owns it, the method `passkey`, and the passkey's id in `credentialId`.
 * Never carries the credential id, the public key, the user handle or the sign
 * count.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyUsed extends ContextEvent {}
