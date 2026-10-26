<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Thrown when the JWT configuration is missing required fields or holds
 * unusable signing material (an unsupported algorithm, or an empty or too-short
 * key) when the `JwtTokenService` is resolved.
 *
 * Fail-closed: an empty or weak signing key would let tokens be forged, so the
 * package refuses to resolve until the consumer configures a real key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidJwtConfigurationException extends \RuntimeException {}
