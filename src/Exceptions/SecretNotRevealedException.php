<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown when a `Secret` is cast, encoded, serialised or unserialised instead
 * of being revealed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretNotRevealedException extends \LogicException
{
    /**
     * Build the exception for a secret used in the way named.
     *
     * @param  string  $use
     * @return self
     */
    public static function for(string $use): self
    {
        return new self("A secret cannot be {$use}: call reveal() where it is to be sent.");
    }
}
