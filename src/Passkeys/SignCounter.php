<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * The sign counter rule a passkey assertion is held to, against the count the
 * passkey's row stores.
 *
 * An authenticator that keeps a counter moves it forward on every assertion, so
 * an assertion whose count is not above the stored one may come from a clone of
 * the authenticator. With `s` the stored count and `p` the assertion's:
 *
 * - `s = 0` and `p = 0`: accepted, and the count stays 0. An authenticator
 *   without a counter (most synced passkeys) always reports 0.
 * - `p > s`: accepted, and the count becomes `p`, by a compare-and-set on `s`,
 *   so of two assertions read against the same count only one moves it; the
 *   other is refused as a regression.
 * - otherwise (`p <= s` with `s > 0`, `p = 0` included): refused as
 *   `passkey_counter_regressed`, a possible clone. Nothing is written, so a
 *   clone cannot lock the genuine authenticator out; the owner can remove the
 *   passkey.
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
