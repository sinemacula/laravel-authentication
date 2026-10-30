<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

/**
 * The password policy's verdict on a new password: every rule it breaks, in the
 * order the policy checks them, or none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordCheck
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>  $violations
     */
    public function __construct(

        /** The rules the password breaks; empty when it passes. */
        public array $violations,
    ) {}

    /**
     * Whether the password breaks no rule.
     *
     * @return bool
     */
    public function passes(): bool
    {
        return $this->violations === [];
    }
}
