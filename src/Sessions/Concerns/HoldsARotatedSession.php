<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;

/**
 * The outcome of a refresh or a switch that a refresh token proves.
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
     * A copy of the outcome recording where the refresh token was read from.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return self
     */
    public function withSource(RefreshTokenSource $source): self
    {
        return new self($this->session, $this->reason, $this->retryAfter, $source, $this->pending, $this->credential);
    }

    /**
     * Whether the call was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->session === null && $this->pending === null;
    }

    /**
     * Whether the session returned to pending.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->pending !== null;
    }

    /**
     * A call that succeeded; the result using the trait names it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    private static function succeeded(SignedInSession $session): self
    {
        return new self(session: $session);
    }

    /**
     * A call that returned the session to pending; the result using the trait
     * names it `pending()`.
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
