<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown when a credential is issued or rotated with malformed or rejected
 * scopes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidScopeException extends \InvalidArgumentException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  list<string>  $scopes
     */
    public function __construct(

        // What is wrong with the scopes.
        string $message,

        /** The offending scopes; a value that is not a string is named by its type. */
        public readonly array $scopes,
    ) {
        parent::__construct($message);
    }
}
