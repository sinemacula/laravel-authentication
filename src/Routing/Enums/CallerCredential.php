<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Routing\Enums;

/**
 * Which credential a route reads its caller from, for the `me` route binding:
 * the access credential the guard authenticates, unless the route declares the
 * refresh or the pending one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum CallerCredential: string
{
    // The bearer credential the guard authenticates the request with
    case ACCESS = 'access';

    // The refresh credential, on a route declaring `authentication.refresh`
    case REFRESH = 'refresh';

    // The pending credential, on a route declaring `authentication.pending`
    case PENDING = 'pending';
}
