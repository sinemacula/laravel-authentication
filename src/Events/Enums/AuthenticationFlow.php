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

    // A request for a one-time code: a sign-in code or an identifier
    // verification code
    case CODE_REQUEST = 'code_request';

    // A check of an identifier verification code or link
    case IDENTIFIER_VERIFICATION = 'identifier_verification';

    // A request's API key
    case API_KEY = 'api_key';

    // A client credentials exchange for an access token
    case CLIENT_CREDENTIALS = 'client_credentials';

    // A request for a password reset link or code, or a reset with one
    case PASSWORD_RESET = 'password_reset';

    // A request for, or a confirmation of, a change of identifier
    case IDENTIFIER_CHANGE = 'identifier_change';
}
