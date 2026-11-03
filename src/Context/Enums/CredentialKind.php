<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context\Enums;

/**
 * What kind of credential the request presented and the guard authenticated it
 * with (`AuthenticationContext::$credential`); a sign-in or a trusted bind made
 * in the request presented none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CredentialKind: string
{
    // A person's access token, of a session or in access-only mode
    case ACCESS_TOKEN = 'access_token';

    // An API key, on an `api_key` guard
    case API_KEY = 'api_key';

    // An access token a client credentials exchange issued for an API key
    case CLIENT_CREDENTIALS = 'client_credentials';
}
