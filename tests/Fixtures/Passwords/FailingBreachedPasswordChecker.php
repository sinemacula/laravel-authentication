<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passwords;

use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;

/**
 * A breached-password checker that throws an exception the contract does not
 * name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingBreachedPasswordChecker implements BreachedPasswordChecker
{
    /**
     * Fail, whatever the password.
     *
     * @param  string  $password
     * @return bool
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        throw new \RuntimeException('a bug in the checker');
    }
}
