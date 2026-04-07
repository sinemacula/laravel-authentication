<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

/**
 * Thrown when the configured devices table already exists in the
 * consumer's schema before the shipped migration runs (REQ-13/AC-13).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class DeviceTableAlreadyExistsException extends \RuntimeException {}
