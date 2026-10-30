<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Breached-password checker contract.
 *
 * Tells the password policy whether a new password is one known to have been
 * exposed in a breach, such as a lookup against a breach corpus or a blocklist
 * of common passwords. The package ships no service: the default binding,
 * `NoBreachedPasswordCheck`, finds nothing, so it protects nothing until the
 * application binds its own.
 *
 * It is asked only about a password that already passes the length and
 * composition rules, and never about the automatic rehash on sign-in. When the
 * service cannot answer (a timeout, an outage), throw
 * `BreachedPasswordCheckUnavailableException`: the policy reports it and then
 * fails closed or open as `authentication.passwords.breached.when_unavailable`
 * says. Any other exception propagates. The password is in clear: never log it,
 * and never put it in an exception message.
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
