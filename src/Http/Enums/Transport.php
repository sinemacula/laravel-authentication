<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Enums;

/**
 * How an application's refresh token travels, as its `refresh_token.transport`
 * names it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Transport: string
{
    // The `refresh_token.body_field` or `refresh_token.header`; results carry
    // the token
    case BODY = 'body';

    // The `refresh_token.cookie` only; results carry the cookie alone
    case COOKIE = 'cookie';
}
