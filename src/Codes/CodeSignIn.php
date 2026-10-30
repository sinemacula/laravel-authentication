<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * A one-time code sign-in method: an identifier of one type and the code
 * `Auth::codes($guard)->send()` sent to it.
 *
 * The package registers it as `phone_code`, for phone numbers, and as
 * `email_code`, for email addresses. The input carries the identifier under
 * the identifier type's name (`phone`, `email`), which is also the identity's
 * column it is looked up by, and the code under `code`.
 * An application registers it for another identifier type with
 * `extend('whatsapp_code', fn ($app) => $app->make(CodeSignIn::class, ['type' => 'whatsapp']))`,
 * given a normaliser for the type.
 *
 * The identifier is brought to its normal form by its type's normaliser, and
 * the code must be exactly the configured number of digits; anything else is
 * `invalid_credentials` with nothing counted. The code is checked against the
 * one issued for the guard and identifier whether or not an identity has the
 * identifier, so a guess at an unknown identifier counts against, and locks,
 * that code exactly as one at a known identifier does; for a known identity the
 * check also counts against the account's own limit first. An identity the
 * guard's provider finds holds the identifier only when its own identifier of
 * the type, in its normal form, is exactly the one the code is bound to (see
 * `CodeIdentifiers`), so an identity found by a look-alike is treated as no
 * identity at all. A code that expired or used up its attempts is refused as
 * `code_expired` or `code_exhausted`, which the sign-in's result conceals as
 * `invalid_credentials`. A correct code for an identity whose identifier of the
 * type is not verified is `identifier_unverified`: the code proved the
 * identifier is held, so this tells a guesser nothing, and a code is never sent
 * to an unverified identifier in the first place.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeSignIn implements SignInMethod
{
    /** @var string Name the package registers phone number codes under. */
    public const string PHONE = 'phone_code';

    /** @var string Name the package registers email address codes under. */
    public const string EMAIL = 'email_code';

    /** @var string Input key holding the code. */
    private const string CODE_KEY = 'code';

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodes  $codes
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers  $normalisers
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Type of identifier the method signs in with, which names its input key, its normaliser and the identity's column. */
        private string $type,

        /** The code engine. */
        private OneTimeCodes $codes,

        /** Normalisers that give identifiers their normal form. */
        private IdentifierNormalisers $normalisers,

        /** Gives an identity's own identifier its canonical form, to compare with the bound one. */
        private IdentifierVerifier $verifier,
    ) {
        if (IdentifierType::assertValid($type) === self::CODE_KEY) {
            throw new \InvalidArgumentException(sprintf('A code sign-in method cannot use the identifier type [%s]: its input key holds the code.', self::CODE_KEY));
        }
    }

    /**
     * The type of identifier the method signs in with, whatever the guard.
     *
     * @param  string  $guard
     * @return string
     */
    #[\Override]
    public function identifierType(string $guard): string
    {
        return $this->type;
    }

    /**
     * The identifier the input names under the type's key, when it is a string
     * or a `Stringable`, as given.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    #[\Override]
    public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string
    {
        $identifier = $input[$this->type] ?? null;

        return is_string($identifier) || $identifier instanceof \Stringable ? (string) $identifier : null;
    }

    /**
     * Verify the identifier and code the input carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|Identity
    {
        $binding = $this->binding($request->guard, $request->input);
        $code    = $request->input[self::CODE_KEY] ?? null;

        if ($binding === null || !is_string($code) || !$this->codes->isWellFormed($code)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        $identity = $this->holder($request->provider->retrieveByCredentials([$this->type => $binding->identifier]), $binding);
        $failure  = $identity !== null && !$request->reserveAccountAttempt($identity)
            ? FailureReason::INVALID_CREDENTIALS
            : $this->codes->check($binding, $code, CarbonImmutable::now()->startOfSecond())->failure();

        return $failure ?? $this->accepted($identity);
    }

    /**
     * The sign-in binding of the identifier the input names for the guard, in
     * its normal form, or `null` when it names none the type's normaliser
     * accepts.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return ?\SineMacula\Laravel\Authentication\Codes\CodeBinding
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function binding(string $guard, #[\SensitiveParameter] array $input): ?CodeBinding
    {
        $given      = $this->identifier($guard, $input);
        $identifier = $given === null ? null : $this->normalisers->get($this->type)->normalise($given);

        return $identifier === null ? null : CodeBinding::signIn($guard, $this->type, $identifier);
    }

    /**
     * The identity the provider found, when it holds exactly the bound
     * identifier, read on the write connection; `null` for none, or one found
     * only by a look-alike. An identity that cannot report its identifiers is
     * kept, as it can never be signed in by code anyway.
     *
     * @param  mixed  $found
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     */
    private function holder(mixed $found, CodeBinding $binding): ?Identity
    {
        return match (true) {
            !$found instanceof Identity                => null,
            $found instanceof HasVerifiableIdentifiers => CodeIdentifiers::isHeldBy($found, $binding, $this->verifier) ? $found : null,
            default                                    => $found,
        };
    }

    /**
     * The answer once the code was accepted: the identity, when there is one
     * and it reports its identifier of the type verified (read on the write
     * connection); `identifier_unverified` when it does not; and
     * `invalid_credentials` when no identity has the identifier.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private function accepted(?Identity $identity): FailureReason|Identity
    {
        $type = $this->type;

        return match (true) {
            $identity === null => FailureReason::INVALID_CREDENTIALS,
            $identity instanceof HasVerifiableIdentifiers
                && WriteConnection::during($identity, static fn (): bool => $identity->hasVerifiedIdentifier($type)) => $identity,
            default                                                                                                  => FailureReason::IDENTIFIER_UNVERIFIED,
        };
    }
}
