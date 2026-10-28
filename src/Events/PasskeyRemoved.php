<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when an identity's passkey is removed, only by the call that
 * removed it, and once the removal is committed on the passkey's own connection
 * (never for one that is rolled back).
 *
 * The context carries the guard the passkey was removed through, the client
 * that removed it, the identity that owned it, the method `passkey`, and the
 * removed passkey's id in `credentialId`. A listener that ends the identity's
 * sessions when a sign-in factor goes away can be registered:
 * `RevokeDevicesOnPasskeyRemoval`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyRemoved extends ContextEvent {}
