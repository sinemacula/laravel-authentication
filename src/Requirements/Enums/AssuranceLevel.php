<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements\Enums;

/**
 * The authenticator assurance levels a requirement may ask for, lowest first,
 * by the values a further-factor package reports them with.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AssuranceLevel: string
{
    // Single-factor authentication
    case AAL1 = 'aal1';

    // Two distinct factors
    case AAL2 = 'aal2';

    // Two distinct factors, one a hardware-backed, phishing-resistant
    // authenticator
    case AAL3 = 'aal3';

    /**
     * Whether this level is at least the one given.
     *
     * @param  self  $level
     * @return bool
     */
    public function isAtLeast(self $level): bool
    {
        return $this->rank() >= $level->rank();
    }

    /**
     * The level's place in the order, lowest first.
     *
     * @return int
     */
    private function rank(): int
    {
        return match ($this) {
            self::AAL1 => 1,
            self::AAL2 => 2,
            self::AAL3 => 3,
        };
    }
}
