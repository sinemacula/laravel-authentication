<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Thrown when the JWT configuration is missing required fields or holds
 * unusable signing material.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidJwtConfigurationException extends \RuntimeException {}
