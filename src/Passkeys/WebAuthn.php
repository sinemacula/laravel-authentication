<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
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
 * The package's use of `web-auth/webauthn-lib`: it builds the ceremony options
 * in their WebAuthn JSON form, parses a browser's response, and runs the
 * library's registration and assertion ceremonies against a guard's relying
 * party.
 *
 * Every ceremony requires user verification. Registration asks for a
 * discoverable credential (`residentKey: required`) and no attestation
 * (`attestation: none`). Under `none` a browser may still pass an
 * authenticator's own statement through, so the statement formats the library
 * checks without further dependencies (`none`, which it always supports,
 * `packed`, `fido-u2f`, `android-key`, `tpm`, `apple`) are accepted for their
 * internal consistency, while no trust path, certificate chain or metadata is
 * evaluated and every passkey is recorded as unattested. The credential
 * algorithms offered are ES256, EdDSA (when the sodium extension is loaded) and
 * RS256. The origin must be one of the relying party's exact origins, and a
 * cross-origin (framed) ceremony is refused. The library's own sign counter
 * check is replaced by `DeferredCounterCheck`: the package applies its rule
 * itself, atomically.
 *
 * Stateless between calls: one instance serves every guard, each ceremony built
 * for the relying party it is given.
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

    /** @var \Symfony\Component\Serializer\Serializer The library's serializer. */
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
     * The signature algorithms credentials may use, in order of preference:
     * ES256, EdDSA when it can be verified, and RS256.
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
     * The options of a registration ceremony, in their WebAuthn JSON form: a
     * discoverable credential, user verification required, no attestation, the
     * algorithms offered, and the credentials to exclude (each a raw id with
     * the transports it reported).
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  string  $challenge
     * @param  string  $userHandle
     * @param  string  $userName
     * @param  string  $displayName
     * @param  list<array{0: string, 1: list<string>}>  $exclude
     * @param  int  $timeout
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

        return $this->normalise($options);
    }

    /**
     * The options of an assertion ceremony, in their WebAuthn JSON form: user
     * verification required, and the credentials allowed (none, for a
     * usernameless sign-in).
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  string  $challenge
     * @param  list<array{0: string, 1: list<string>}>  $allow
     * @param  int  $timeout
     * @return array<string, mixed>
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function requestOptions(RelyingParty $rp, string $challenge, array $allow, int $timeout): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $rp->id,
            self::descriptors($allow),
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $timeout,
        );

        return $this->normalise($options);
    }

    /**
     * Parse a browser's response (its `PublicKeyCredential` as JSON, or that
     * JSON decoded), or `null` when it is not a well-formed WebAuthn credential
     * of the `public-key` type: input of any other shape is refused by the
     * library's parsing.
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
     * Run the registration ceremony on the response against the stored creation
     * options and the relying party, and return the credential it registers, or
     * `null` when it does not verify.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $credential
     * @return ?\Webauthn\CredentialRecord
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function register(RelyingParty $rp, array $options, PublicKeyCredential $credential): ?CredentialRecord
    {
        $response = $credential->response;
        $creation = $this->serializer->denormalize($options, PublicKeyCredentialCreationOptions::class, 'json');

        if (!$response instanceof AuthenticatorAttestationResponse) {
            return null;
        }

        $validator = AuthenticatorAttestationResponseValidator::create($this->ceremonies($rp)->creationCeremony());

        return self::refusing(static fn (): CredentialRecord => $validator->check($response, $creation, $rp->id));
    }

    /**
     * Run the assertion ceremony on the response against the stored request
     * options, the relying party and the stored credential, and return the
     * credential as the assertion leaves it (its new count and backup state),
     * or `null` when it does not verify. The user handle is the one the
     * identity was registered under when the ceremony was for a known identity,
     * else `null`, and the response must then carry the credential's own.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $credential
     * @param  \Webauthn\CredentialRecord  $record
     * @param  ?string  $userHandle
     * @return ?\Webauthn\CredentialRecord
     *
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function assert(RelyingParty $rp, array $options, PublicKeyCredential $credential, CredentialRecord $record, ?string $userHandle): ?CredentialRecord
    {
        $response = $credential->response;
        $request  = $this->serializer->denormalize($options, PublicKeyCredentialRequestOptions::class, 'json');

        if (!$response instanceof AuthenticatorAssertionResponse) {
            return null;
        }

        $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonies($rp)->requestCeremony());

        return self::refusing(static fn (): CredentialRecord => $validator->check($record, $response, $request, $rp->id, $userHandle));
    }

    /**
     * Run a step of the library on the response, and answer `null` when it
     * refuses it. The library reports malformed bytes (base64, CBOR, client
     * data) and a response that does not verify by throwing exceptions of every
     * kind; its steps read nothing but the response, the options and the stored
     * credential, so a throw only ever means the response is refused.
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
     * The library's ceremonies, scoped to the relying party's exact origins,
     * with the package's algorithms and statement formats, and the counter
     * check deferred to the package.
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
    private function normalise(PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options): array
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
