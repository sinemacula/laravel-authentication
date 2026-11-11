<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

/**
 * Thrown when an establishment finds the identity's row already holds a
 * password, so its transaction rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PasswordAlreadySet extends \RuntimeException
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct('The identity already has a password, so none was established.');
    }
}
