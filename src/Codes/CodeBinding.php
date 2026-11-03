<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * What a one-time code challenge is bound to: its purpose, its guard, the
 * identifier's type (or the channel's kind) and normal form, and, for a code
 * that verifies an identifier, proves a new one or is a further factor's, the
 * identity it is for; these form the challenge's delivery key, of which one
 * live challenge exists. A further factor's challenge is also bound to its
 * transaction (the session, the factor and the proof's purpose or enrolment
 * grant), which the key leaves out, so a new transaction replaces the challenge
 * without a new delivery window. A code checked against any other key or
 * transaction does not match.
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
     * @param  string  $transaction
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

        /** The identity a verification, change or factor code is for (see `AccountAttempts::account()`, then the change request), or empty for a sign-in or reset code. */
        public string $identity,

        /** The transaction a factor code is bound to besides its key, or empty for every other purpose. */
        #[\SensitiveParameter] public string $transaction = '',
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
        return new self(CodePurpose::VERIFICATION, $guard, $type, $identifier, AccountAttempts::account($identity));
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

    /**
     * The binding of a further factor's code, or of an enrolment's: the
     * destination of its channel under the channel's kind, and the identity it
     * is for, as its key, and the session, the factor and the proof's purpose
     * (for an enrolment, the grant) as its transaction.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return self
     */
    public static function factor(string $guard, FactorCodeBinding $binding): self
    {
        $proof       = $binding->binding;
        $last        = $proof->purpose === Purpose::ENROLLMENT ? (string) $binding->grant : $proof->purpose->value;
        $transaction = implode("\0", [(string) IdentifierCoercion::stringify($proof->sessionId), $binding->factor, $last]);

        $channel = $binding->channel;

        return new self($binding->purpose(), $guard, $channel->kind->value, (string) $channel->reference, AccountAttempts::account($proof->identity), $transaction);
    }
}
