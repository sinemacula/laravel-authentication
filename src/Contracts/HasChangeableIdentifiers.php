<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Lets an identity replace an identifier with one it has proven.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasChangeableIdentifiers extends HasVerifiableIdentifiers
{
    /**
     * Replace the identifier of the type with `$replacement`, recorded as
     * verified, atomically and only while it is still exactly `$current`.
     *
     * @param  string  $type
     * @param  ?string  $current
     * @param  string  $replacement
     * @return bool
     *
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     *
     * @imperative
     */
    public function replaceIdentifier(string $type, ?string $current, string $replacement): bool;
}
