<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

/**
 * The one rule for a reference the factor package hands this package, to a
 * factor or an enrolment grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorReference
{
    /** @var int Longest reference accepted, in characters: the width of `proofs.factor_reference`. */
    public const int MAX_LENGTH = 255;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the reference is given, not empty and no longer than
     * `MAX_LENGTH`.
     *
     * @param  ?string  $reference
     * @return bool
     */
    public static function isValid(#[\SensitiveParameter] ?string $reference): bool
    {
        return $reference !== null && $reference !== '' && mb_strlen($reference) <= self::MAX_LENGTH;
    }
}
