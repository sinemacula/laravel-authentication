<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys\Enums;

/**
 * How registering a passkey ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PasskeyRegistrationStatus: string
{
    // The passkey was stored for the identity
    case REGISTERED = 'registered';

    // The challenge is unknown, expired, already answered, or not a
    // registration challenge of this guard and identity
    case CHALLENGE_INVALID = 'challenge_invalid';

    // The response is malformed, or does not verify against the challenge's
    // options and the guard's relying party
    case RESPONSE_INVALID = 'response_invalid';

    // The credential is already registered
    case ALREADY_REGISTERED = 'already_registered';
}
