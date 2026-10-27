<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: an identity can report and record whether each of its
 * identifiers (its email address, its phone number) has been verified.
 *
 * Optional supplement to `Identity`, required by the verification helpers and
 * by a guard that sets `require_verified_identifier`. Each method takes the
 * identifier type (`email`, `phone`): a lower-case letter followed by
 * lower-case letters, digits and underscores. The package calls the readers
 * inside `WriteConnection::during()` for the identity, so a verified state read
 * from the database comes from the write connection.
 * `ProvidesIdentifierVerification` implements it from a column per type and a
 * `<type>_verified_at` column beside it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasVerifiableIdentifiers
{
    /**
     * The identity's current identifier of the type, or `null` when it has
     * none.
     *
     * @param  string  $type
     * @return ?string
     */
    public function getIdentifierForVerification(string $type): ?string;

    /**
     * Whether the identity's current identifier of the type has been verified.
     *
     * @param  string  $type
     * @return bool
     */
    public function hasVerifiedIdentifier(string $type): bool;

    /**
     * Record the identifier of the type as verified, provided it is still the
     * identity's identifier, exactly as given, and is not verified already.
     * Returns whether this call recorded it; the check and the record must be
     * one atomic step, so a proof for one address can never verify another.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    public function markIdentifierAsVerified(string $type, string $identifier): bool;
}
