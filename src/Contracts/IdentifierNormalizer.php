<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Brings an identifier a person types to the one form it is stored and looked
 * up in; must be deterministic and idempotent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentifierNormalizer
{
    /**
     * Return the identifier in its normal form, or `null` when the value cannot
     * be an identifier of this type.
     *
     * @param  string  $identifier
     * @return ?string
     */
    public function normalize(#[\SensitiveParameter] string $identifier): ?string;
}
