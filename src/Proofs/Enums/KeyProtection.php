<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * How the key behind a proof was observed to be protected.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyProtection: string
{
    // The key is held in hardware
    case HARDWARE = 'hardware';

    // The key is held in software
    case SOFTWARE = 'software';
}
