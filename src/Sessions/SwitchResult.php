<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

/**
 * The outcome of switching a session to another principal: the session on the
 * same device with its new token pair, or why it was refused.
 *
 * A refused switch leaves the session as it was (unless the presented refresh
 * token proved a replay, which revokes the device), and `AuthenticationFailed`
 * reports why; `retryAfter` carries the wait of a `rate_limited` refusal. A
 * switch read from the request (`switchPrincipalFromRequest()`) says where the
 * refresh token came from (`source`), so one read from the cookie can be
 * answered with a cookie.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SwitchResult
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

        /** The session acting as the new principal, when the switch succeeded. */
        public ?SignedInSession $session = null,

        /** Why the switch was refused, when it was. */
        public ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,

        /** Where the refresh token was read from, for a switch read from the request. */
        public ?RefreshTokenSource $source = null,
    ) {}

    /**
     * A switch that succeeded.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return self
     */
    public static function switched(SignedInSession $session): self
    {
        return new self(session: $session);
    }

    /**
     * A switch that was refused.
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
     * Whether the session now acts as the new principal.
     *
     * @return bool
     */
    public function isSwitched(): bool
    {
        return $this->session !== null;
    }

    /**
     * Whether the switch was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->session === null;
    }
}
