<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown by a `BreachedPasswordChecker` that cannot answer; its message must
 * never hold the password.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BreachedPasswordCheckUnavailableException extends \RuntimeException {}
