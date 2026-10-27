<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Identifier normaliser contract.
 *
 * Brings an identifier a person types (an email address, a phone number) to the
 * one form it is stored and looked up in, so `Ben@Example.com ` and
 * `ben@example.com` name the same account on every database, whatever its
 * collation. A normaliser is registered under the name of the identifier type
 * it serves (`email`, later `phone`) in `authentication.identifiers`, and is
 * applied when a designated identifier is set (`Casts\NormalisedIdentifier`),
 * when the `model` provider looks one up, and when attempts are counted.
 *
 * Implementations must be stateless and deterministic: the same input always
 * gives the same output, and normalising an already normalised value returns it
 * unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentifierNormaliser
{
    /**
     * Return the identifier in its normal form, or `null` when the value cannot
     * be an identifier of this type.
     *
     * @param  string  $identifier
     * @return ?string
     */
    public function normalise(#[\SensitiveParameter] string $identifier): ?string;
}
