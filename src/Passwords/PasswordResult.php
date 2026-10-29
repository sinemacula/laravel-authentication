<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

/**
 * What `set()` did: set the password, after which the sessions its flow ends
 * were revoked; or nothing, because the password breaks the policy.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordResult
{
    /**
     * Constructor.
     *
     * @param  bool  $set
     * @param  list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>  $violations
     * @param  int  $revoked
     */
    private function __construct(

        /** Whether the password was set. */
        public bool $set,

        /** The rules the password breaks, when it was not set. */
        public array $violations,

        /** How many devices the flow revoked, when it was set. */
        public int $revoked,
    ) {}

    /**
     * The password was set, and the flow revoked this many devices.
     *
     * @param  int  $revoked
     * @return self
     */
    public static function set(int $revoked): self
    {
        return new self(true, [], $revoked);
    }

    /**
     * The password breaks the policy, so nothing was written.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>  $violations
     * @return self
     */
    public static function rejected(array $violations): self
    {
        return new self(false, $violations, 0);
    }

    /**
     * Whether the password was set.
     *
     * @return bool
     */
    public function isSet(): bool
    {
        return $this->set;
    }
}
