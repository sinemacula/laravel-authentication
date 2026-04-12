<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Thrown when the JWT configuration is missing required fields when the
 * `JwtTokenService` is resolved.
 *
 * Fail-closed: an empty signing secret would silently accept forged tokens, so
 * the package refuses to resolve until the consumer configures a real secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidJwtConfigurationException extends \RuntimeException {}
