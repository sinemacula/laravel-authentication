<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Why the engine delivered no code for a key, and for how long: the resend
 * cooldown since the last delivery has not passed, or the key's delivery window
 * has had all the deliveries it allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveryRefusal
{
    /**
     * Constructor.
     *
     * @param  int  $retryAfter
     * @param  bool  $exhausted
     */
    private function __construct(

        /** Seconds, at least 1, until another delivery may be made. */
        public int $retryAfter,

        /** Whether the delivery window has had all its deliveries, rather than the cooldown not having passed. */
        public bool $exhausted,
    ) {}

    /**
     * A code was delivered for the key within the resend cooldown.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function cooldown(int $retryAfter): self
    {
        return new self(max(1, $retryAfter), false);
    }

    /**
     * The key's delivery window has had `max_deliveries` deliveries; another
     * may be made once it ends.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function exhausted(int $retryAfter): self
    {
        return new self(max(1, $retryAfter), true);
    }

    /**
     * How a request answers the refusal: `deliveries_exhausted` or
     * `rate_limited`, with the wait.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     */
    public function request(): CodeRequest
    {
        return $this->exhausted ? CodeRequest::deliveriesExhausted($this->retryAfter) : CodeRequest::rateLimited($this->retryAfter);
    }

    /**
     * The reason `AuthenticationFailed` reports the refusal with.
     *
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public function reason(): FailureReason
    {
        return $this->exhausted ? FailureReason::DELIVERIES_EXHAUSTED : FailureReason::RATE_LIMITED;
    }
}
