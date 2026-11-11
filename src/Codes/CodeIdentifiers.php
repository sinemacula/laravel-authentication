<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * An identity's own identifier of a type, read on the write connection in its
 * canonical form, compared byte for byte with a code's bound identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeIdentifiers
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The identity's current identifier of the type in its canonical form, or
     * `null` when it has none the type's normaliser accepts.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function of(HasVerifiableIdentifiers&Identity $identity, string $type, IdentifierVerifier $verifier): ?string
    {
        $current = WriteConnection::during($identity, static fn (): ?string => $identity->getIdentifierForVerification($type));

        return $current === null ? null : $verifier->canonical($type, $current);
    }

    /**
     * Whether the identity's own identifier of the binding's type is exactly
     * the one the binding names.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function isHeldBy(HasVerifiableIdentifiers&Identity $identity, CodeBinding $binding, IdentifierVerifier $verifier): bool
    {
        $own = self::of($identity, $binding->type, $verifier);

        return $own !== null && hash_equals($binding->identifier, $own);
    }
}
