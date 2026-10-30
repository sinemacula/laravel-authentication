<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;

/**
 * The default breached-password checker: finds no password breached, so the
 * policy blocks nothing on that ground until the application binds a checker of
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoBreachedPasswordCheck implements BreachedPasswordChecker
{
    /**
     * No password is known to be breached.
     *
     * @param  string  $password
     * @return bool
     */
    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        return false;
    }
}
