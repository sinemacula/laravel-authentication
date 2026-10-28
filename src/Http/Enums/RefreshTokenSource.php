<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Enums;

/**
 * Where a request carried its refresh token, as a guard's `refresh_token`
 * `sources` name it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RefreshTokenSource: string
{
    // The guard's HttpOnly `refresh_token.cookie`
    case COOKIE = 'cookie';

    // The guard's `refresh_token.body_field`, in the JSON or form body
    case BODY = 'body';

    // The guard's `refresh_token.header`
    case HEADER = 'header';
}
