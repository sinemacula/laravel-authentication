<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords\Enums;

/**
 * Why a password is being set, which decides what else `set()` does: a
 * registration ends no session, a change ends every session but the one it was
 * made from when the caller keeps it, and a reset ends every session. Choose it
 * on the server, never from input: a registration revokes nothing.
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
}
