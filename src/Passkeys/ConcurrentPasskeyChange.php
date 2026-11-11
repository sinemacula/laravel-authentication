<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * Thrown when a passkey write finds the change already made by another request,
 * so the transaction rolls back the factor gate's work too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConcurrentPasskeyChange extends \RuntimeException {}
