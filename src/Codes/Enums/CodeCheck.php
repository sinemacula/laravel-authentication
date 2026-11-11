<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The outcome of checking a one-time code against the one issued for a binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum CodeCheck: string
{
    // The code matched the live code, which this check used up
    case ACCEPTED = 'accepted';

    // The issuance read was replaced or deleted before an attempt could be
    // counted against it
    case INVALID = 'invalid';

    // No code was issued for the binding, it was replaced, or the challenge or
    // its transaction is another; no attempt was counted
    case NOT_FOUND = 'not_found';

    // The binding's challenge was used up, by an accepted code or by being
    // ended; no attempt was counted
    case USED = 'used';

    // The code was checked against the live code, its attempt counted, and did
    // not match it, or another check used the code up first
    case WRONG = 'wrong';

    // The code issued for the binding has expired
    case EXPIRED = 'expired';

    // The code issued for the binding has used up its attempts
    case EXHAUSTED = 'exhausted';

    /**
     * Why a check that did not accept the code failed, as a failure reason, or
     * `null` for one that did.
     *
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public function failure(): ?FailureReason
    {
        return match ($this) {
            self::ACCEPTED  => null,
            self::EXPIRED   => FailureReason::CODE_EXPIRED,
            self::EXHAUSTED => FailureReason::CODE_EXHAUSTED,
            self::INVALID,
            self::NOT_FOUND,
            self::USED,
            self::WRONG => FailureReason::INVALID_CREDENTIALS,
        };
    }
}
