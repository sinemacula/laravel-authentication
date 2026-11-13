<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Database\Eloquent\Collection;

/**
 * An identity that can report and record whether each of its identifiers has
 * been verified.
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
     * Record the identifier of the type as verified, atomically and only while
     * it is still exactly the identity's and not verified already.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    public function markIdentifierAsVerified(string $type, string $identifier): bool;

    /**
     * The identities whose identifier of the type is the given one, in its
     * normal form, and verified.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&static>
     *
     * @throws \InvalidArgumentException
     */
    public static function holdingVerifiedIdentifier(string $type, #[\SensitiveParameter] string $identifier): Collection;
}
