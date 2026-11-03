<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * Thrown inside a passkey's registration or removal transaction when its write
 * finds the change already made by another (a credential registered, or a
 * passkey removed, meanwhile), so the transaction rolls back everything done in
 * it, the factor gate's work included. The passkey service catches it outside
 * the transaction and answers with the outcome; it never leaves the service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConcurrentPasskeyChange extends \RuntimeException {}
