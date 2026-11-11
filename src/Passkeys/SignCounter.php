<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * The sign counter rule a passkey assertion is held to, against the count the
 * passkey's row stores.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignCounter
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether an assertion that presents the count may be accepted against the
     * stored count.
     *
     * @param  int  $stored
     * @param  int  $presented
     * @return bool
     */
    public static function accepts(int $stored, int $presented): bool
    {
        return $presented > $stored || ($stored === 0 && $presented === 0);
    }
}
