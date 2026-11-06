<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials\Enums;

/**
 * How a client credentials token request authenticated the client, by the
 * client authentication method names RFC 7591 registers.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ClientAuthentication: string
{
    // HTTP Basic, the id and secret each form-url-encoded (RFC 6749 section
    // 2.3.1)
    case BASIC = 'client_secret_basic';

    // `client_id` and `client_secret` in the form body, which the application
    // must allow
    case POST = 'client_secret_post';
}
