<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown when a `Secret` is cast to a string, encoded as JSON, serialised or
 * unserialised instead of being revealed. Each of those would send or keep the
 * secret without anyone having asked for it, so it is a bug in the calling
 * code: it fails loudly rather than carrying the secret on, or carrying a
 * placeholder where a client expected it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretNotRevealedException extends \LogicException
{
    /**
     * The exception for a secret used in the way named, such as `cast to a
     * string`.
     *
     * @param  string  $use
     * @return self
     */
    public static function for(string $use): self
    {
        return new self("A secret cannot be {$use}: call reveal() where it is to be sent.");
    }
}
