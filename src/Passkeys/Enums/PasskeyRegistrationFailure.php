<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys\Enums;

/**
 * Why a passkey was not registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PasskeyRegistrationFailure: string
{
    // The challenge is unknown, expired, already answered, or not a
    // registration challenge of this guard and identity
    case CHALLENGE_INVALID = 'challenge_invalid';

    // The response is malformed, or does not verify against the challenge's
    // options and the guard's relying party
    case RESPONSE_INVALID = 'response_invalid';

    // The credential is already registered
    case ALREADY_REGISTERED = 'already_registered';
}
