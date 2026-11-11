<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords\Enums;

/**
 * Why a password is being set, which decides which sessions end; choose it on
 * the server, never from input.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PasswordFlow: string
{
    // The identity's first password, set by the application's registration
    case REGISTRATION = 'registration';

    // A password the signed-in identity chose to replace its own with
    case CHANGE = 'change';

    // A password set after proving control of an identifier, without the old
    // one
    case RESET = 'reset';

    // A first password a signed-in identity that had none chose
    case ESTABLISHMENT = 'establishment';
}
