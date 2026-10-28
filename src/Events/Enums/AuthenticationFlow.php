<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * The flow an `AuthenticationFailed` event reports a failure of.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AuthenticationFlow: string
{
    // A sign-in: attempt(), and the session service's signIn(), start(),
    // complete(), choose() and discard()
    case SIGN_IN = 'sign_in';

    // A request's access token
    case BEARER = 'bearer';

    // A refresh-token exchange: refresh() and refreshFromRequest()
    case REFRESH = 'refresh';

    // A switch of the principal a device's session acts as
    case PRINCIPAL_SWITCH = 'principal_switch';
}
