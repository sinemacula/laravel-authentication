<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * A one-time code sign-in method: an identifier of one type and the code
 * `Auth::codes($guard)->send()` sent to it.
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

    /** @var string Input key holding the challenge's id. */
    private const string CHALLENGE_KEY = 'challenge';

    /** @var array<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind, 1: string}> The channel and `amr` value of each identifier type a code is sent through, by type. */
    private const array CHANNELS = [
        'email' => [ChannelKind::EMAIL, 'otp'],
        'phone' => [ChannelKind::SMS, 'sms'],
    ];

    /** @var string The `amr` value of a code sent through any other identifier type. */
    private const string OTHER_AMR = 'otp';

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodes  $codes
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers  $normalizers
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
        private IdentifierNormalizers $normalizers,

        /** Gives an identity's own identifier its canonical form, to compare with the bound one. */
        private IdentifierVerifier $verifier,
    ) {
        if (in_array(IdentifierType::assertValid($type), [self::CODE_KEY, self::CHALLENGE_KEY], true)) {
            throw new \InvalidArgumentException(sprintf('A code sign-in method cannot use the identifier type [%s]: its input key holds the code or its challenge.', $type));
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
     * The challenge id the input answers, when it is in the form the engine
     * issues: a lower-case UUID.
     *
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    #[\Override]
    public function challenge(#[\SensitiveParameter] array $input): ?string
    {
        $challenge = $input[self::CHALLENGE_KEY] ?? null;

        return is_string($challenge) && $this->codes->isWellFormedChallenge($challenge) ? $challenge : null;
    }

    /**
     * Verify the identifier and code the input carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|FirstFactor
    {
        $binding   = $this->binding($request->guard, $request->input());
        $code      = $request->input()[self::CODE_KEY]      ?? null;
        $challenge = $request->input()[self::CHALLENGE_KEY] ?? null;

        if ($binding === null || !is_string($code) || !is_string($challenge) || !$this->isWellFormed($code, $challenge)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        $identity = $this->holder($request->provider->retrieveByCredentials([$this->type => $binding->identifier]), $binding);
        $failure  = $identity !== null && !$request->reserveAccountAttempt($identity)
            ? FailureReason::INVALID_CREDENTIALS
            : $this->codes->check($binding, $challenge, $code, CarbonImmutable::now()->startOfSecond())->failure();

        $accepted = $failure ?? $this->accepted($identity);

        return $accepted instanceof Identity ? $this->firstFactor($accepted, $binding) : $accepted;
    }

    /**
     * The sign-in binding of the identifier the input names, or `null` when it
     * names none the type's normaliser accepts.
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
        $identifier = $given === null ? null : $this->normalizers->get($this->type)->normalize($given);

        return $identifier === null ? null : CodeBinding::signIn($guard, $this->type, $identifier);
    }

    /**
     * Whether the code and the challenge id have the shapes the engine issues
     * them in.
     *
     * @param  string  $code
     * @param  string  $challenge
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isWellFormed(#[\SensitiveParameter] string $code, string $challenge): bool
    {
        return $this->codes->isWellFormed($code) && $this->codes->isWellFormedChallenge($challenge);
    }

    /**
     * The identity the provider found, when it holds exactly the bound
     * identifier or cannot report its identifiers, otherwise `null`.
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
     * The first factor a verified code proves, over the channel of the method's
     * identifier type.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Proofs\FirstFactor
     */
    private function firstFactor(Identity $identity, CodeBinding $binding): FirstFactor
    {
        [$kind, $amr] = self::CHANNELS[$this->type] ?? [ChannelKind::UNKNOWN, self::OTHER_AMR];

        $length      = mb_strlen($binding->identifier);
        $destination = $length > 0 && $length <= Channel::REFERENCE_MAX_LENGTH ? $binding->identifier : null;

        return new FirstFactor($identity, new Channel($kind, $destination), methods: [$amr]);
    }

    /**
     * The answer once the code was accepted: the identity when it reports its
     * identifier of the type verified, otherwise why not.
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
