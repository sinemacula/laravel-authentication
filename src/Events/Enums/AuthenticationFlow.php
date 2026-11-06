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
    // signInExternally(), satisfy() and choose()
    case SIGN_IN = 'sign_in';

    // A request's access token
    case BEARER = 'bearer';

    // A refresh-token exchange: the session service's refresh()
    case REFRESH = 'refresh';

    // A switch of the principal a session acts as, its active tenant, or both:
    // the session service's switchTo()
    case SWITCH = 'switch';

    // A sign-out by refresh credential: the session service's signOutWith()
    case SIGN_OUT = 'sign_out';

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

    // A step-up of an active session with a further factor: the session
    // service's stepUp()
    case STEP_UP = 'step_up';

    // A reauthentication of an active session with the first factor, or at the
    // external provider it began with: the session service's reauthenticate()
    // and reauthenticateExternally()
    case REAUTHENTICATION = 'reauthentication';

    // A request for, or a check of, a further factor's code or an enrolment's:
    // the code service's sendFactorCode() and verifyFactorCode()
    case FACTOR_CODE = 'factor_code';

    // A change or an establishment of the password from a signed-in session:
    // the password service's change() and establish()
    case PASSWORD_CHANGE = 'password_change';

    // A recheck of the current session after one of the factor package's
    // factors was removed or changed: the session service's factorRemoved() and
    // factorChanged()
    case FACTOR_CHANGE = 'factor_change';
}
