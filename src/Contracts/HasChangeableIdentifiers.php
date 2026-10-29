<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: an identity whose identifiers (its email address, its
 * phone number) can be replaced by one it has proven, atomically.
 *
 * Optional supplement to `Identity`, required by `Auth::identifierChanges()`.
 * It extends `HasVerifiableIdentifiers`, since a replacement is recorded as
 * verified: it was proven before it was set. `ProvidesIdentifierVerification`
 * implements it from a column per type and a `<type>_verified_at` column beside
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasChangeableIdentifiers extends HasVerifiableIdentifiers
{
    /**
     * Replace the identifier of the type with `$replacement` and record it as
     * verified now, provided the identity's identifier is still exactly
     * `$current` (`null` for none); returns whether this call replaced it. The
     * check and the write must be one atomic step on the identity's connection
     * (the row read under a lock, or one conditional statement), so a change
     * proven against one identifier can never overwrite another. A violation of
     * the application's unique index on the identifier propagates as Laravel's
     * `UniqueConstraintViolationException`.
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
