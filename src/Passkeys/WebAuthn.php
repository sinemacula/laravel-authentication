<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Serializer;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The package's use of `web-auth/webauthn-lib`: ceremony options, response
 * parsing and the registration and assertion ceremonies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WebAuthn
{
    /** @var string Type of every WebAuthn credential. */
    public const string PUBLIC_KEY = 'public-key';

    /** @var int Deepest nesting a response's JSON may have. */
    private const int MAX_DEPTH = 16;

    /** @var \Cose\Algorithm\Manager The signature algorithms credentials may use. */
    private Manager $algorithms;

    /** @var \Webauthn\AttestationStatement\AttestationStatementSupportManager The attestation statement formats accepted. */
    private AttestationStatementSupportManager $statements;

    /** @var \Symfony\Component\Serializer\Serializer The library's serialiser. */
    private Serializer $serializer;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->algorithms = self::algorithms(EdDSA::isSupported());
        $this->statements = AttestationStatementSupportManager::create([
            PackedAttestationStatementSupport::create($this->algorithms),
            FidoU2FAttestationStatementSupport::create(),
            AndroidKeyAttestationStatementSupport::create(),
            TPMAttestationStatementSupport::create(),
            AppleAttestationStatementSupport::create(),
        ]);

        $serializer = (new WebauthnSerializerFactory($this->statements))->create();

        assert($serializer instanceof Serializer);

        $this->serializer = $serializer;
    }

    /**
     * The signature algorithms credentials may use, in order of preference.
     *
     * @param  bool  $eddsa
     * @return \Cose\Algorithm\Manager
     */
    public static function algorithms(bool $eddsa): Manager
    {
        return $eddsa
            ? Manager::create()->add(ES256::create(), new EdDSA, RS256::create())
            : Manager::create()->add(ES256::create(), RS256::create());
    }

    /**
     * The options of a registration ceremony, in their WebAuthn JSON form.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  string  $challenge
     * @param  string  $userHandle
     * @param  string  $userName
     * @param  string  $displayName
     * @param  list<array{0: string, 1: list<string>}>  $exclude
     * @param  positive-int  $timeout
     * @return array<string, mixed>
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function creationOptions(RelyingParty $rp, string $challenge, string $userHandle, string $userName, string $displayName, array $exclude, int $timeout): array
    {
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($rp->name, $rp->id),
            PublicKeyCredentialUserEntity::create($userName, $userHandle, $displayName),
            $challenge,
            array_map(PublicKeyCredentialParameters::createPk(...), [...$this->algorithms->list()]),
            AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            self::descriptors($exclude),
            $timeout,
        );

        return $this->normalize($options);
    }

    /**
     * The options of an assertion ceremony, in their WebAuthn JSON form.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  string  $challenge
     * @param  list<array{0: string, 1: list<string>}>  $allow
     * @param  positive-int  $timeout
     * @param  bool  $requireUserVerification
     * @return array<string, mixed>
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function requestOptions(RelyingParty $rp, string $challenge, array $allow, int $timeout, bool $requireUserVerification = true): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $rp->id,
            self::descriptors($allow),
            $requireUserVerification
                ? PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
                : PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $timeout,
        );

        return $this->normalize($options);
    }

    /**
     * Parse a browser's response, or `null` when it is not a well-formed
     * `public-key` credential.
     *
     * @param  array<array-key, mixed>|string  $credential
     * @return ?\Webauthn\PublicKeyCredential
     */
    public function credential(#[\SensitiveParameter] array|string $credential): ?PublicKeyCredential
    {
        $decoded = is_string($credential) ? json_decode($credential, true, self::MAX_DEPTH) : $credential;
        $parsed  = self::refusing(fn (): PublicKeyCredential => $this->serializer->denormalize($decoded, PublicKeyCredential::class, 'json'));

        return $parsed?->type === self::PUBLIC_KEY ? $parsed : null;
    }

    /**
     * Run the registration ceremony on the response and return the credential
     * with what it showed, or `null` when it does not verify.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $credential
     * @return ?array{0: \Webauthn\CredentialRecord, 1: \SineMacula\Laravel\Authentication\Proofs\ObservedProperties}
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function register(RelyingParty $rp, array $options, PublicKeyCredential $credential): ?array
    {
        $response = $credential->response;
        $creation = $this->serializer->denormalize($options, PublicKeyCredentialCreationOptions::class, 'json');

        if (!$response instanceof AuthenticatorAttestationResponse || $response->clientDataJSON->crossOrigin) {
            return null;
        }

        $validator = AuthenticatorAttestationResponseValidator::create($this->ceremonies($rp)->creationCeremony());
        $record    = self::refusing(static fn (): CredentialRecord => $validator->check($response, $creation, $rp->id));

        return $record === null ? null : [$record, self::observed($response->attestationObject->authData)];
    }

    /**
     * Run the assertion ceremony on the response and return the credential as
     * it leaves it with what it showed, or `null` when it does not verify.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $credential
     * @param  \Webauthn\CredentialRecord  $record
     * @param  ?string  $userHandle
     * @return ?array{0: \Webauthn\CredentialRecord, 1: \SineMacula\Laravel\Authentication\Proofs\ObservedProperties}
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function assert(RelyingParty $rp, array $options, PublicKeyCredential $credential, CredentialRecord $record, ?string $userHandle): ?array
    {
        $response = $credential->response;
        $request  = $this->serializer->denormalize($options, PublicKeyCredentialRequestOptions::class, 'json');

        if (!$response instanceof AuthenticatorAssertionResponse || $response->clientDataJSON->crossOrigin) {
            return null;
        }

        $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonies($rp)->requestCeremony());
        $verified  = self::refusing(static fn (): CredentialRecord => $validator->check($record, $response, $request, $rp->id, $userHandle));

        return $verified === null ? null : [$verified, self::observed($response->authenticatorData)];
    }

    /**
     * What the authenticator data's flags showed, resistant to phishing since
     * the origin was verified.
     *
     * @param  \Webauthn\AuthenticatorData  $data
     * @return \SineMacula\Laravel\Authentication\Proofs\ObservedProperties
     */
    private static function observed(AuthenticatorData $data): ObservedProperties
    {
        return new ObservedProperties($data->isUserPresent(), $data->isUserVerified(), $data->isBackupEligible(), $data->isBackedUp(), true);
    }

    /**
     * Run a step of the library on the response, and answer `null` when it
     * throws, as it does for any refused response.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $step
     * @return ?TResult
     */
    private static function refusing(\Closure $step): mixed
    {
        try {
            return $step();
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The library's ceremonies, scoped to the relying party's exact origins.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @return \Webauthn\CeremonyStep\CeremonyStepManagerFactory
     */
    private function ceremonies(RelyingParty $rp): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory;

        $factory->setAllowedOrigins($rp->origins);
        $factory->setAlgorithmManager($this->algorithms);
        $factory->setAttestationStatementSupportManager($this->statements);
        $factory->setCounterChecker(new DeferredCounterCheck);

        return $factory;
    }

    /**
     * Normalise ceremony options to their WebAuthn JSON form.
     *
     * @param  \Webauthn\PublicKeyCredentialCreationOptions|\Webauthn\PublicKeyCredentialRequestOptions  $options
     * @return array<string, mixed>
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    private function normalize(PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options): array
    {
        /** @var array<string, mixed> */
        return $this->serializer->normalize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
    }

    /**
     * Credential descriptors for raw ids and their transports.
     *
     * @param  list<array{0: string, 1: list<string>}>  $ids
     * @return list<\Webauthn\PublicKeyCredentialDescriptor>
     */
    private static function descriptors(array $ids): array
    {
        return array_map(static fn (array $id): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(self::PUBLIC_KEY, $id[0], $id[1]), $ids);
    }
}
