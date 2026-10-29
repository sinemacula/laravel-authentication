<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown when a credential is issued or rotated with scopes that are malformed
 * (not RFC 6749 scope tokens) or that the scope registry rejects. Issuing a
 * credential is a trusted, programmatic action, so a bad scope is the caller's
 * error rather than a failed authentication.
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
