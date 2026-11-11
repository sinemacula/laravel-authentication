<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys\Enums;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration;

/**
 * Why a passkey challenge could not be consumed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ChallengeRefusal
{
    // The id is malformed or names no challenge, or the challenge belongs to
    // another ceremony, guard, relying party, owner or binding
    case NOT_FOUND;

    // The challenge is the response's own, unused, and past its lifetime
    case EXPIRED;

    // The challenge is the response's own and a response was submitted to it
    // before, whether or not that one authenticated
    case USED;

    /**
     * The failure reason a sign-in or factor verification reports for the
     * refusal.
     *
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public function reason(): FailureReason
    {
        return match ($this) {
            self::NOT_FOUND => FailureReason::PASSKEY_CHALLENGE_INVALID,
            self::EXPIRED   => FailureReason::PASSKEY_CHALLENGE_EXPIRED,
            self::USED      => FailureReason::PASSKEY_CHALLENGE_USED,
        };
    }

    /**
     * The registration a registration ceremony answers for the refusal.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration
     */
    public function registration(): PasskeyRegistration
    {
        return match ($this) {
            self::NOT_FOUND => PasskeyRegistration::challengeInvalid(),
            self::EXPIRED   => PasskeyRegistration::challengeExpired(),
            self::USED      => PasskeyRegistration::challengeUsed(),
        };
    }
}
