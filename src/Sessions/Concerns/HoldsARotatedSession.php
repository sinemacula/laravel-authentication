<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;

/**
 * The shape of the outcome of a call a refresh token proves, a refresh or a
 * switch: the same session with its rotated token pair; the session returned to
 * pending, with the pending credential it now holds instead, when it fell short
 * of a further factor it can meet in place; or why the call was refused, with
 * the wait of a `rate_limited` refusal and, for a call that read the token from
 * the request, where it was read from. The result using it names its success,
 * aliasing `succeeded()` and `hasSucceeded()`, and its return to pending,
 * aliasing `returned()` as `pending()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait HoldsARotatedSession
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     */
    private function __construct(

        /** The session with its new token pair, when the call succeeded. */
        public readonly ?SignedInSession $session = null,

        /** Why the call was refused, when it was. */
        public readonly ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public readonly ?int $retryAfter = null,

        /** Where the refresh token was read from, for a call that read it from the request. */
        public readonly ?RefreshTokenSource $source = null,

        /** The session, returned to pending, when it fell short of a further factor. */
        public readonly ?PendingSession $pending = null,

        /** The pending credential the returned session now holds. */
        public readonly ?Secret $credential = null,
    ) {}

    /**
     * A call that was refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function failed(FailureReason $reason, ?int $retryAfter = null): self
    {
        return new self(reason: $reason, retryAfter: $retryAfter);
    }

    /**
     * A copy of the outcome that says the refresh token was read from the
     * source; the outcome itself is left as it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return self
     */
    public function withSource(RefreshTokenSource $source): self
    {
        return new self($this->session, $this->reason, $this->retryAfter, $source, $this->pending, $this->credential);
    }

    /**
     * Whether the call was refused: it neither re-issued the pair nor returned
     * the session to pending.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->session === null && $this->pending === null;
    }

    /**
     * Whether the session returned to pending instead of being re-issued its
     * pair.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->pending !== null;
    }

    /**
     * A call that succeeded, with the session on its new token pair; the result
     * using the trait names it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    private static function succeeded(SignedInSession $session): self
    {
        return new self(session: $session);
    }

    /**
     * A call that returned the session to pending, with the pending credential
     * it now holds; the result using the trait names it `pending()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @return self
     */
    private static function returned(PendingSession $pending, Secret $credential): self
    {
        return new self(pending: $pending, credential: $credential);
    }

    /**
     * Whether the call succeeded; the result using the trait names it.
     *
     * @return bool
     */
    private function hasSucceeded(): bool
    {
        return $this->session !== null;
    }
}
