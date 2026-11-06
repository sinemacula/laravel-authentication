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

    // The challenge is malformed, unknown, or not a registration challenge of
    // this guard and identity
    case CHALLENGE_INVALID = 'challenge_invalid';

    // The identity's registration challenge expired before it was answered
    case CHALLENGE_EXPIRED = 'challenge_expired';

    // A response was submitted to the identity's registration challenge before,
    // whether or not that one registered a passkey
    case CHALLENGE_USED = 'challenge_used';

    // The response is malformed, or does not verify against the challenge's
    // options and the guard's relying party
    case RESPONSE_INVALID = 'response_invalid';

    // The credential is already registered
    case ALREADY_REGISTERED = 'already_registered';
}
