<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Secrets;

/**
 * The plaintext of a secret handed in either as the `Secret` the package
 * returned or as the string a request carried, for the step that must read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Plaintext
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The value in clear: a `Secret` revealed, a string as it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $value
     * @return string
     */
    public static function of(#[\SensitiveParameter] Secret|string $value): string
    {
        return $value instanceof Secret ? $value->reveal() : $value;
    }
}
