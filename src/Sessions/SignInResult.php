<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;

/**
 * How a sign-in, or an action on its pending session, ended: an active session,
 * a pending session or a failure.
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
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** How the sign-in ended. */
        public SignInStatus $status,

        /** The session that activated, when one did. */
        public ?SignedInSession $session = null,

        /** The session waiting on requirements, when it is pending. */
        public ?PendingSession $pending = null,

        /** The pending credential, when the call issued one. */
        public ?Secret $credential = null,

        /** Why the sign-in failed, when it did. */
        public ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * A sign-in whose session activated.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    public static function signedIn(SignedInSession $session): self
    {
        return new self(SignInStatus::SIGNED_IN, session: $session);
    }

    /**
     * A sign-in whose session waits on requirements, with the pending
     * credential when the call issued one.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @return self
     */
    public static function pending(PendingSession $pending, ?Secret $credential = null): self
    {
        return new self(SignInStatus::PENDING, pending: $pending, credential: $credential);
    }

    /**
     * A sign-in that failed, with a concealed reason answered as
     * `invalid_credentials`.
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
     * Whether the session activated.
     *
     * @return bool
     */
    public function isSignedIn(): bool
    {
        return $this->status === SignInStatus::SIGNED_IN;
    }

    /**
     * Whether the session waits on requirements.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->status === SignInStatus::PENDING;
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
