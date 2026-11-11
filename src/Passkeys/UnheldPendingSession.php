<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * Thrown when the pending credential handed in proves no pending session the
 * registration may hold, so its transaction rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnheldPendingSession extends \RuntimeException {}
