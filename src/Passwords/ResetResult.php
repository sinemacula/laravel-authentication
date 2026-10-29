<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;

/**
 * How a password reset ended: the password set, with how many devices were
 * revoked; refused as invalid, without saying why; rate limited, with the
 * seconds to wait; or rejected by the password policy, with the rules the new
 * password breaks.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResetResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus  $status
     * @param  list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>  $violations
     * @param  ?int  $retryAfter
     * @param  int  $revoked
     */
    private function __construct(

        /** How the reset ended. */
        public ResetStatus $status,

        /** The rules the new password breaks, for `password_rejected` only. */
        public array $violations = [],

        /** Seconds until another reset may be tried, for `rate_limited` only. */
        public ?int $retryAfter = null,

        /** How many devices the reset revoked, for `reset` only. */
        public int $revoked = 0,
    ) {}

    /**
     * The password was set, and this many devices revoked.
     *
     * @param  int  $revoked
     * @return self
     */
    public static function reset(int $revoked): self
    {
        return new self(ResetStatus::RESET, revoked: $revoked);
    }

    /**
     * The identifier, token or code was not accepted, or the identity may not
     * reset its password.
     *
     * @return self
     */
    public static function invalid(): self
    {
        return new self(ResetStatus::INVALID);
    }

    /**
     * No reset may be tried for the identifier, or from the IP address, for the
     * seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function rateLimited(int $retryAfter): self
    {
        return new self(ResetStatus::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * The new password breaks the policy.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>  $violations
     * @return self
     */
    public static function passwordRejected(array $violations): self
    {
        return new self(ResetStatus::PASSWORD_REJECTED, $violations);
    }

    /**
     * Whether the password was set.
     *
     * @return bool
     */
    public function isReset(): bool
    {
        return $this->status === ResetStatus::RESET;
    }
}
