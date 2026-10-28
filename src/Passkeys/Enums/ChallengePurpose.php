<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys\Enums;

/**
 * The ceremony a passkey challenge is for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ChallengePurpose: string
{
    // Registering a passkey for an identity
    case REGISTER = 'register';

    // A usernameless sign-in
    case SIGN_IN = 'sign_in';

    // Verifying one of an identity's passkeys as a further factor
    case FACTOR = 'factor';
}
