<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials\Enums;

/**
 * How a client credentials token request authenticated the client, by the RFC
 * 7591 method names.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ClientAuthentication: string
{
    // HTTP Basic, the id and secret each form-url-encoded
    case BASIC = 'client_secret_basic';

    // `client_id` and `client_secret` in the form body
    case POST = 'client_secret_post';
}
