<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * What `set()`, `change()` or `establish()` did: set the password, or nothing
 * and why.
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
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** Whether the password was set. */
        public bool $set,

        /** The rules the password breaks, when it was not set. */
        public array $violations,

        /** How many sessions the flow revoked, when it was set. */
        public int $revoked,

        /** Why a change or an establishment was refused before the policy judged the password, when it was. */
        public ?FailureReason $reason = null,

        /** Seconds until the current password may be checked again, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * The password was set, and the flow revoked this many sessions.
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
     * A change or an establishment was refused for the reason given, so nothing
     * was written.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function refused(FailureReason $reason, ?int $retryAfter = null): self
    {
        return new self(false, [], 0, $reason, $retryAfter);
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
