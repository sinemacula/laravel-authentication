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

    // The pending credential handed in names no live pending session of this
    // identity on this guard (or none that the challenge was bound to): the
    // check does not say which
    case PENDING_INVALID = 'pending_invalid';

    // A cookie application's request that did not come from a page of its own
    // site, refused before the pending session was read
    case CROSS_SITE_REQUEST = 'cross_site_request';
}
