<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown by a `BreachedPasswordChecker` that cannot answer, so the password
 * policy can tell an outage from a verdict: it reports the exception and then
 * rejects the password or lets it through, as
 * `authentication.passwords.breached.when_unavailable` says. Its message must
 * never hold the password.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BreachedPasswordCheckUnavailableException extends \RuntimeException {}
