<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;

/**
 * What a one-time code is bound to: its purpose, its guard, the identifier's
 * type and normal form, and, for a code that verifies an identifier or proves a
 * new one, the identity it is for. One live code exists per binding, and a code
 * checked against any other binding does not match.
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

        /** The identity a verification or change code is for (see `AccountAttempts::account()`, then the change request), or empty for a sign-in or reset code. */
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

    /**
     * The binding of a password reset code: no identity, since a reset code is
     * issued whether or not any identity has the identifier.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @return self
     */
    public static function passwordReset(string $guard, string $type, #[\SensitiveParameter] string $identifier): self
    {
        return new self(CodePurpose::PASSWORD_RESET, $guard, $type, $identifier, '');
    }

    /**
     * The binding of a password reset link's token: no identity, as for a reset
     * code, and a purpose of its own, so a token never checks as a code.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @return self
     */
    public static function passwordResetLink(string $guard, string $type, #[\SensitiveParameter] string $identifier): self
    {
        return new self(CodePurpose::PASSWORD_RESET_LINK, $guard, $type, $identifier, '');
    }

    /**
     * The binding of a code that proves the new identifier of one change
     * request of the identity: bound to the request too, so a newer request's
     * code is another binding and an earlier request's code never confirms it.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $requestId
     * @return self
     */
    public static function identifierChange(string $guard, string $type, #[\SensitiveParameter] string $identifier, Identity $identity, string $requestId): self
    {
        return new self(CodePurpose::CHANGE_IDENTIFIER, $guard, $type, $identifier, AccountAttempts::account($identity) . "\0" . $requestId);
    }
}
