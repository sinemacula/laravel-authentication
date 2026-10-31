<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Identifier normalizer contract.
 *
 * Brings an identifier a person types (an email address, a phone number) to the
 * one form it is stored and looked up in, so `Ben@Example.com ` and
 * `ben@example.com` name the same account on every database, whatever its
 * collation. A normalizer is registered under the name of the identifier type
 * it serves (`email`, later `phone`) in `authentication.identifiers`, and is
 * applied when a designated identifier is set (`Casts\NormalizedIdentifier`),
 * when the `model` provider looks one up, and when attempts are counted.
 *
 * Implementations must be stateless and deterministic: the same input always
 * gives the same output, and normalizing an already normalized value returns it
 * unchanged.
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
