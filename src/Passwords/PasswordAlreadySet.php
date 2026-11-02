<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

/**
 * Thrown by an establishment's write when the identity's row already holds a
 * password, so its transaction rolls back and the establishment is refused as
 * `password_already_set`; never seen outside the package.
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
