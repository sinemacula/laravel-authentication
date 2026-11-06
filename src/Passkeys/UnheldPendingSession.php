<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * Thrown inside a passkey's registration transaction when the pending
 * credential handed in does not prove a live pending session of the identity on
 * the guard (and the one the challenge was bound to), so the transaction rolls
 * back before the factor gate is asked. The passkey service catches it outside
 * the transaction and answers `pending_invalid`; it never leaves the service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnheldPendingSession extends \RuntimeException {}
