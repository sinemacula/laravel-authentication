<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;

/**
 * What a one-time code is bound to: its purpose, its guard, the identifier's
 * type and normal form, and, for a code that verifies an identifier, the
 * identity it verifies. One live code exists per binding, and a code checked
 * against any other binding does not match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeBinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @param  string  $identity
     */
    private function __construct(

        /** What the code is for. */
        public CodePurpose $purpose,

        /** Guard the code is for. */
        public string $guard,

        /** Type of the identifier, for example `phone`. */
        public string $type,

        /** The identifier, in its normal form. */
        #[\SensitiveParameter] public string $identifier,

        /** The identity a verification code is for (see `AccountAttempts::account()`), or empty for a sign-in code. */
        public string $identity,
    ) {}

    /**
     * The binding of a sign-in code: no identity, since a sign-in code is
     * issued whether or not any identity has the identifier.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @return self
     */
    public static function signIn(string $guard, string $type, #[\SensitiveParameter] string $identifier): self
    {
        return new self(CodePurpose::SIGN_IN, $guard, $type, $identifier, '');
    }

    /**
     * The binding of a code that verifies the identity's identifier, so it
     * verifies that identity's identifier and no other's.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return self
     */
    public static function verification(string $guard, string $type, #[\SensitiveParameter] string $identifier, Identity $identity): self
    {
        return new self(CodePurpose::VERIFY_IDENTIFIER, $guard, $type, $identifier, AccountAttempts::account($identity));
    }
}
