<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Callers\Enums;

/**
 * Which credential a request's caller was read from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
