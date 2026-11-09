<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console\Enums;

/**
 * How serious a configuration check's finding is: an error fails
 * `authentication:check`, as a failing built-in validation does, and a warning
 * is shown without changing the exit code.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FindingSeverity: string
{
    // The configuration is wrong: the command exits non-zero
    case ERROR = 'error';

    // The configuration works but is likely not what was meant: shown only
    case WARNING = 'warning';
}
