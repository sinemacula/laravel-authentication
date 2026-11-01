<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * How the key behind a proof was observed to be protected: in hardware or in
 * software. Not observed at all is no value, never either of these.
 *
 * The values are the further-factor package's own.
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
