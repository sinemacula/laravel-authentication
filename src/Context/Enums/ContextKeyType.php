<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context\Enums;

/**
 * The type of the value an authentication context key holds when it is not
 * `null`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextKeyType: string
{
    // A string
    case STRING = 'string';

    // A list of strings
    case LIST = 'list';

    // An integer
    case NUMBER = 'number';

    // A boolean
    case BOOL = 'bool';

    // An IPv4 or IPv6 address, as a string
    case IP = 'ip';

    // An instant, as Unix seconds
    case TIME = 'time';
}
