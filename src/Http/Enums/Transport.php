<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Enums;

/**
 * How an application's refresh token travels, as its `refresh_token.transport`
 * names it: in the body, where the client keeps it, or only in an `HttpOnly`
 * cookie the browser keeps, which no script can read.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Transport: string
{
    // The `refresh_token.body_field` of the JSON or form body, or the
    // `refresh_token.header` when one is set; results carry the token
    case BODY = 'body';

    // The application's `refresh_token.cookie` only; results carry the cookie
    // that sets it, never the token
    case COOKIE = 'cookie';
}
