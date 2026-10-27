<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;

/**
 * How a sign-in through the session service ended: a started session, a
 * pending sign-in waiting for a further factor, or a failure with its reason
 * (and, for `rate_limited`, the seconds until the next attempt may be made). A
 * failure is a result rather than an exception, so the caller answers it as it
 * chooses; exceptions are kept for misconfiguration and server errors.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus  $status
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingFactor  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** How the sign-in ended. */
        public SignInStatus $status,

        /** The session that started, when one did. */
        public ?SignedInSession $session = null,

        /** The pending sign-in waiting for a further factor, when one is required. */
        public ?PendingFactor $pending = null,

        /** Why the sign-in failed, when it did. */
        public ?SignInFailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * A sign-in that started the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    public static function signedIn(SignedInSession $session): self
    {
        return new self(SignInStatus::SIGNED_IN, session: $session);
    }

    /**
     * A sign-in that needs a further factor before its session may start.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingFactor  $pending
     * @return self
     */
    public static function pendingFactor(PendingFactor $pending): self
    {
        return new self(SignInStatus::FACTOR_REQUIRED, pending: $pending);
    }

    /**
     * A sign-in that failed.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function failed(SignInFailureReason $reason, ?int $retryAfter = null): self
    {
        return new self(SignInStatus::FAILED, reason: $reason, retryAfter: $retryAfter);
    }

    /**
     * Whether a session started.
     *
     * @return bool
     */
    public function isSignedIn(): bool
    {
        return $this->status === SignInStatus::SIGNED_IN;
    }

    /**
     * Whether a further factor is required before the session may start.
     *
     * @return bool
     */
    public function requiresFactor(): bool
    {
        return $this->status === SignInStatus::FACTOR_REQUIRED;
    }

    /**
     * Whether the sign-in failed.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->status === SignInStatus::FAILED;
    }
}
