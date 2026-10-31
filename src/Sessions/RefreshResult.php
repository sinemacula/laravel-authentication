<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

/**
 * The outcome of refreshing a session: the session on the same device with its
 * rotated token pair, or why the refresh was refused.
 *
 * A refused refresh leaves the session as it was (unless the presented refresh
 * token proved a replay, which revokes the device), and `Failed` and
 * `AuthenticationFailed` report why; `retryAfter` carries the wait of a
 * `rate_limited` refusal. A refresh read from the request
 * (`refreshFromRequest()`) says where the refresh token came from (`source`),
 * so one read from the cookie can be answered with a cookie.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     */
    private function __construct(

        /** The refreshed session with its new token pair, when the refresh succeeded. */
        public ?SignedInSession $session = null,

        /** Why the refresh was refused, when it was. */
        public ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,

        /** Where the refresh token was read from, for a refresh read from the request. */
        public ?RefreshTokenSource $source = null,
    ) {}

    /**
     * A refresh that succeeded.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    public static function refreshed(SignedInSession $session): self
    {
        return new self(session: $session);
    }

    /**
     * A refresh that was refused.
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
        return new self($this->session, $this->reason, $this->retryAfter, $source);
    }

    /**
     * Whether the session was refreshed.
     *
     * @return bool
     */
    public function isRefreshed(): bool
    {
        return $this->session !== null;
    }

    /**
     * Whether the refresh was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->session === null;
    }
}
