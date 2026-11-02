<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

/**
 * The one rule for a reference the factor package hands this package: its
 * reference to a factor (the one a change acts on, a removal removes, a passkey
 * is associated as, or a code is bound to) or to an enrolment grant. Each is
 * from 1 to 255 characters, the width `proofs.factor_reference` holds, so a
 * reference accepted anywhere is one a proof can record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorReference
{
    /** @var int Longest reference accepted, in characters. */
    public const int MAX_LENGTH = 255;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the reference is one this package accepts: given, not empty, and
     * no longer than the longest accepted.
     *
     * @param  ?string  $reference
     * @return bool
     */
    public static function isValid(#[\SensitiveParameter] ?string $reference): bool
    {
        return $reference !== null && $reference !== '' && mb_strlen($reference) <= self::MAX_LENGTH;
    }
}
