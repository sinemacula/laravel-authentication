<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Tells the password policy whether a new password is known to have been
 * exposed in a breach. The password is in clear: never log it or put it in an
 * exception message.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface BreachedPasswordChecker
{
    /**
     * Whether the password is known to have been breached.
     *
     * @param  string  $password
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException
     */
    public function isBreached(#[\SensitiveParameter] string $password): bool;
}
