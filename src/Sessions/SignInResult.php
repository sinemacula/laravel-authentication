<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;

/**
 * How a sign-in through the session service ended: a started session, a pending
 * sign-in waiting for a further factor, a sign-in waiting for its identity to
 * choose a principal, or a failure with its reason (and, for `rate_limited`,
 * the seconds until the next attempt may be made). A failure is a result rather
 * than an exception, so the caller answers it as it chooses; exceptions are
 * kept for misconfiguration and server errors.
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
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PrincipalChoice  $choice
     */
    private function __construct(

        /** How the sign-in ended. */
        public SignInStatus $status,

        /** The session that started, when one did. */
        public ?SignedInSession $session = null,

        /** The pending sign-in waiting for a further factor, when one is required. */
        public ?PendingFactor $pending = null,

        /** Why the sign-in failed, when it did. */
        public ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,

        /** The choice of principal the identity must make, when one is required. */
        public ?PrincipalChoice $choice = null,
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
     * A sign-in that waits for its identity to choose the principal its session
     * acts as.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PrincipalChoice  $choice
     * @return self
     */
    public static function principalRequired(PrincipalChoice $choice): self
    {
        return new self(SignInStatus::PRINCIPAL_REQUIRED, choice: $choice);
    }

    /**
     * A sign-in that failed. A concealed reason (a refusal by the account's own
     * limit, an expired or exhausted code, a passkey's sign counter that did
     * not advance) is answered as `invalid_credentials`, with no wait, as a
     * wrong secret would be, so the result never reveals that the account or a
     * code exists; only the server-side `AuthenticationFailed` event says why.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function failed(FailureReason $reason, ?int $retryAfter = null): self
    {
        if ($reason->isConcealed()) {
            return new self(SignInStatus::FAILED, reason: FailureReason::INVALID_CREDENTIALS);
        }

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
     * Whether the identity must choose a principal before the session may
     * start.
     *
     * @return bool
     */
    public function requiresPrincipal(): bool
    {
        return $this->status === SignInStatus::PRINCIPAL_REQUIRED;
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
