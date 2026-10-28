<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;
use SineMacula\Laravel\Authentication\Passkeys\WebAuthn;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;

/**
 * Tests for the package's use of the WebAuthn library: the options it builds,
 * the responses it parses, and the registration and assertion ceremonies it
 * runs against a relying party, with real keys from the virtual authenticator.
 * Run in the application, whose error handler turns what the library's parsing
 * of malformed input raises into exceptions, as it does for every request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WebAuthn::class)]
final class WebAuthnTest extends TestCase
{
    /** @var string The relying party id. */
    private const string RP_ID = 'example.test';

    /** @var string The origin the ceremonies run on. */
    private const string ORIGIN = 'https://app.example.test';

    /** @var int The timeout the options carry, in milliseconds. */
    private const int TIMEOUT = 300000;

    /** @var \SineMacula\Laravel\Authentication\Passkeys\WebAuthn The wrapper under test. */
    private WebAuthn $webauthn;

    /** @var \SineMacula\Laravel\Authentication\Passkeys\RelyingParty The relying party of the ceremonies. */
    private RelyingParty $rp;

    /**
     * Build the wrapper and the relying party.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->webauthn = new WebAuthn;
        $this->rp       = self::relyingParty([self::ORIGIN]);
    }

    /**
     * ES256, EdDSA and RS256 are offered in that order, and EdDSA only when it
     * can be verified.
     *
     * @return void
     */
    public function testTheAlgorithmsAreOfferedInOrderOfPreference(): void
    {
        self::assertSame([-7, -8, -257], array_values([...WebAuthn::algorithms(true)->list()]));
        self::assertSame([-7, -257], array_values([...WebAuthn::algorithms(false)->list()]));
    }

    /**
     * Registration options ask for a discoverable credential with user
     * verification and no attestation, name the relying party and the user
     * under the handle given, offer the algorithms, exclude the credentials
     * given with their transports, and carry the challenge and the timeout,
     * binary members in base64url and no null members.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRegistrationOptionsAskForADiscoverableVerifiedUnattestedCredential(): void
    {
        $exclude = [['credential-1', ['usb']], ['credential-2', []]];
        $options = $this->webauthn->creationOptions($this->rp, 'challenge-bytes', 'handle-bytes', 'ada', 'Ada Lovelace', $exclude, self::TIMEOUT);

        self::assertSame([
            'challenge'        => VirtualAuthenticator::encode('challenge-bytes'),
            'timeout'          => self::TIMEOUT,
            'rp'               => ['id' => self::RP_ID, 'name' => 'Example'],
            'user'             => ['id' => VirtualAuthenticator::encode('handle-bytes'), 'name' => 'ada', 'displayName' => 'Ada Lovelace'],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -8],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'authenticatorSelection' => ['requireResidentKey' => true, 'userVerification' => 'required', 'residentKey' => 'required'],
            'attestation'            => 'none',
            'excludeCredentials'     => [
                ['type' => 'public-key', 'id' => VirtualAuthenticator::encode('credential-1'), 'transports' => ['usb']],
                ['type' => 'public-key', 'id' => VirtualAuthenticator::encode('credential-2')],
            ],
        ], $options);
    }

    /**
     * Request options require user verification, name the relying party and the
     * credentials allowed (none for a usernameless sign-in), and carry the
     * challenge and the timeout.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestOptionsRequireUserVerification(): void
    {
        self::assertSame([
            'challenge'        => VirtualAuthenticator::encode('challenge-bytes'),
            'timeout'          => self::TIMEOUT,
            'rpId'             => self::RP_ID,
            'allowCredentials' => [],
            'userVerification' => 'required',
        ], $this->webauthn->requestOptions($this->rp, 'challenge-bytes', [], self::TIMEOUT));

        $allowed = $this->webauthn->requestOptions($this->rp, 'challenge-bytes', [['credential-1', ['internal']]], self::TIMEOUT);

        self::assertSame([['type' => 'public-key', 'id' => VirtualAuthenticator::encode('credential-1'), 'transports' => ['internal']]], $allowed['allowCredentials']);
    }

    /**
     * A response parses from its JSON or from that JSON decoded, to the same
     * credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResponseParsesFromJsonOrFromItsDecodedForm(): void
    {
        $response = (new VirtualAuthenticator(self::ORIGIN))->create($this->creation());

        $fromArray = $this->webauthn->credential($response);
        $fromJson  = $this->webauthn->credential((string) json_encode($response));

        self::assertNotNull($fromArray);
        self::assertNotNull($fromJson);
        self::assertSame(VirtualAuthenticator::decode(VirtualAuthenticator::at($response, 'id')), $fromArray->rawId);
        self::assertSame($fromArray->rawId, $fromJson->rawId);
    }

    /**
     * Rows of `[credential]`: responses that are not a well-formed WebAuthn
     * credential, given as JSON or decoded, each made from a valid registration
     * or assertion response as far as it goes.
     *
     * @return iterable<string, array{0: \Closure(array<string, mixed>, array<string, mixed>): (array<array-key, mixed>|string)}>
     */
    public static function provideMalformedCredentials(): iterable
    {
        yield from [
            'not JSON'                             => [static fn (array $registration): string => '{"id":'],
            'JSON that is not an object'           => [static fn (array $registration): string => '"credential"'],
            'JSON nested too deeply'               => [static fn (array $registration): string => str_repeat('[', 20) . str_repeat(']', 20)],
            'no id'                                => [static fn (array $registration): array => self::without($registration, 'id')],
            'an id that is not a string'           => [static fn (array $registration): array => ['id' => 7] + $registration],
            'no raw id'                            => [static fn (array $registration): array => self::without($registration, 'rawId')],
            'a raw id that is not a string'        => [static fn (array $registration): array => ['rawId' => ['x']] + $registration],
            'an id and raw id that differ'         => [static fn (array $registration): array => ['rawId' => VirtualAuthenticator::encode('another id')] + $registration],
            'no type'                              => [static fn (array $registration): array => self::without($registration, 'type')],
            'another type'                         => [static fn (array $registration): array => ['type' => 'password'] + $registration],
            'no response'                          => [static fn (array $registration): array => self::without($registration, 'response')],
            'a response that is not an object'     => [static fn (array $registration): array => ['response' => 'response'] + $registration],
            'no client data'                       => [static fn (array $registration): array => self::response($registration, ['clientDataJSON' => null])],
            'client data that is not a string'     => [static fn (array $registration): array => self::response($registration, ['clientDataJSON' => 12])],
            'client data that is not JSON'         => [static fn (array $registration): array => self::response($registration, ['clientDataJSON' => 'ew'])],
            'client data that is not base64url'    => [static fn (array $registration): array => self::response($registration, ['clientDataJSON' => '%%%'])],
            'an attestation that is not a string'  => [static fn (array $registration): array => self::response($registration, ['attestationObject' => false])],
            'an attestation that is not CBOR'      => [static fn (array $registration): array => self::response($registration, ['attestationObject' => '__-_'])],
            'neither an attestation nor signature' => [static fn (array $registration): array => self::response($registration, ['attestationObject' => null])],
            'authenticator data not a string'      => [static fn (array $registration, array $assertion): array => self::response($assertion, ['authenticatorData' => 1])],
            'authenticator data that is too short' => [static fn (array $registration, array $assertion): array => self::response($assertion, ['authenticatorData' => 'AAAA'])],
            'a signature that is not a string'     => [static fn (array $registration, array $assertion): array => self::response($assertion, ['signature' => 1.5])],
            'a user handle that is not a string'   => [static fn (array $registration, array $assertion): array => self::response($assertion, ['userHandle' => 99])],
        ];
    }

    /**
     * A malformed response parses to nothing, without an exception.
     *
     * @param  \Closure(array<string, mixed>, array<string, mixed>): (array<array-key, mixed>|string)  $malformed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedCredentials')]
    public function testAMalformedResponseParsesToNothing(\Closure $malformed): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);

        $this->registered($authenticator, 'handle-bytes');

        $registration = $authenticator->create($this->creation());
        $assertion    = $authenticator->get($this->request());

        self::assertNotNull($this->webauthn->credential($assertion));
        self::assertNull($this->webauthn->credential($malformed($registration, $assertion)));
    }

    /**
     * Members a response may leave out or leave empty parse: no transports, and
     * a user handle that is `null`, empty or absent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOptionalMembersMayBeLeftOut(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);

        $this->registered($authenticator, 'handle-bytes');

        $registration = $authenticator->create($this->creation());
        $assertion    = $authenticator->get($this->request());
        $explicit     = self::response($assertion, ['userHandle' => 'placeholder']);

        assert(is_array($explicit['response']));

        $explicit['response']['userHandle'] = null;

        self::assertNotNull($this->webauthn->credential(self::response($registration, ['transports' => null])));
        self::assertNotNull($this->webauthn->credential($explicit));
        self::assertNotNull($this->webauthn->credential(self::response($assertion, ['userHandle' => ''])));
        self::assertNotNull($this->webauthn->credential(self::response($assertion, ['userHandle' => null])));
    }

    /**
     * Rows of `[algorithm, format]`: every algorithm offered, attested with
     * `none` and with a packed self attestation.
     *
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function provideAuthenticators(): iterable
    {
        foreach (['ES256' => VirtualAuthenticator::ES256, 'EdDSA' => VirtualAuthenticator::EDDSA, 'RS256' => VirtualAuthenticator::RS256] as $name => $algorithm) {
            foreach (['none', 'packed'] as $format) {
                yield "{$name}, {$format} attestation" => [$algorithm, $format];
            }
        }
    }

    /**
     * A registration verifies for every algorithm offered and both statement
     * formats, and the credential it registers carries the authenticator's id,
     * the options' user handle, the transports, a count of 0, the backup state
     * and user verification; an assertion with it then verifies and moves its
     * count.
     *
     * @param  int  $algorithm
     * @param  string  $format
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAuthenticators')]
    public function testARegisteredCredentialThenAssertsForEveryAlgorithm(int $algorithm, string $format): void
    {
        $authenticator         = new VirtualAuthenticator(self::ORIGIN, $algorithm);
        $authenticator->format = $format;

        $record = $this->registered($authenticator, 'handle-bytes');

        self::assertSame(VirtualAuthenticator::decode($authenticator->lastCredentialId()), $record->publicKeyCredentialId);
        self::assertSame('handle-bytes', $record->userHandle);
        self::assertSame(['internal', 'hybrid'], $record->transports);
        self::assertSame(0, $record->counter);
        self::assertTrue($record->backupEligible);
        self::assertTrue($record->backupStatus);
        self::assertTrue($record->uvInitialized);

        $verified = $this->asserted($authenticator, $record, null);

        self::assertSame(1, $verified?->counter);
    }

    /**
     * Rows of `[change]`: what makes a registration response fail its ceremony.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void}>
     */
    public static function provideRegistrationFaults(): iterable
    {
        yield from [
            'an origin not listed' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'https://evil.test';
            }],
            'a listed origin over http' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'http://app.example.test';
            }],
            'a subdomain of a listed origin' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'https://deep.app.example.test';
            }],
            'another relying party id hash' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->rpId = 'other.test';
            }],
            'no user verification' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->userVerified = false;
            }],
            'no user presence' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->userPresent = false;
            }],
            'a framed ceremony' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->topOrigin = 'https://frame.test';
            }],
            'a framed ceremony reported only as cross-origin' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->crossOrigin = true;
            }],
            'a backed-up ineligible key' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->backupEligible = false;
            }],
        ];
    }

    /**
     * A registration from the wrong origin or relying party, without user
     * verification or presence, framed, or with inconsistent backup bits, is
     * refused without an exception.
     *
     * @param  \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void  $fault
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRegistrationFaults')]
    public function testAFaultyRegistrationIsRefused(\Closure $fault): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);

        $fault($authenticator);

        $options  = $this->creation();
        $response = $this->webauthn->credential($authenticator->create($options));

        self::assertNotNull($response);
        self::assertNull($this->webauthn->register($this->rp, $options, $response));
    }

    /**
     * A registration answering other options (another challenge) is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationForAnotherChallengeIsRefused(): void
    {
        $response = $this->webauthn->credential((new VirtualAuthenticator(self::ORIGIN))->create($this->creation()));

        self::assertNotNull($response);
        self::assertNull($this->webauthn->register($this->rp, $this->creation(), $response));
    }

    /**
     * An assertion response is not a registration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionIsNotARegistration(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);

        $this->registered($authenticator, 'handle-bytes');

        $assertion = $this->webauthn->credential($authenticator->get($this->request()));

        self::assertNotNull($assertion);
        self::assertNull($this->webauthn->register($this->rp, $this->creation(), $assertion));
    }

    /**
     * A registration is not an assertion.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationIsNotAnAssertion(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');
        $registration  = $this->webauthn->credential($authenticator->create($this->creation()));

        self::assertNotNull($registration);
        self::assertNull($this->webauthn->assert($this->rp, $this->request(), $registration, $record, null));
    }

    /**
     * Rows of `[change]`: what makes an assertion fail its ceremony.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void}>
     */
    public static function provideAssertionFaults(): iterable
    {
        yield from [
            'an origin not listed' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'https://evil.test';
            }],
            'another relying party id hash' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->rpId = 'other.test';
            }],
            'no user verification' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->userVerified = false;
            }],
            'no user presence' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->userPresent = false;
            }],
            'a framed ceremony' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->topOrigin = 'https://frame.test';
            }],
            'a framed ceremony reported only as cross-origin' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->crossOrigin = true;
            }],
        ];
    }

    /**
     * An assertion from the wrong origin or relying party, without user
     * verification or presence, or framed, is refused.
     *
     * @param  \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void  $fault
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAssertionFaults')]
    public function testAFaultyAssertionIsRefused(\Closure $fault): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');

        $fault($authenticator);

        self::assertNull($this->asserted($authenticator, $record, null));
    }

    /**
     * An assertion whose signature does not verify, or that answers other
     * options, is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionWithABadSignatureOrForAnotherChallengeIsRefused(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');
        $options       = $this->request();
        $response      = $authenticator->get($options);

        $signature = VirtualAuthenticator::decode(VirtualAuthenticator::at($response, 'response', 'signature'));
        $forged    = self::response($response, ['signature' => VirtualAuthenticator::encode(substr($signature, 0, -1) . chr(ord($signature[-1]) ^ 1))]);

        self::assertNull($this->webauthn->assert($this->rp, $options, $this->parsed($forged), $record, null));
        self::assertNull($this->webauthn->assert($this->rp, $this->request(), $this->parsed($response), $record, null));
        self::assertNotNull($this->webauthn->assert($this->rp, $options, $this->parsed($response), $record, null));
    }

    /**
     * Usernameless, the response must carry the credential's own user handle;
     * for a known identity, the handle given must be the credential's, and a
     * response that carries none is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUserHandleMustBeTheCredentials(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');

        $options  = $this->request();
        $response = $authenticator->get($options);
        $other    = self::response($response, ['userHandle' => VirtualAuthenticator::encode('other-handle')]);
        $none     = self::response($response, ['userHandle' => null]);

        self::assertNull($this->webauthn->assert($this->rp, $options, $this->parsed($other), $record, null));
        self::assertNull($this->webauthn->assert($this->rp, $options, $this->parsed($none), $record, null));
        self::assertNull($this->webauthn->assert($this->rp, $options, $this->parsed($response), $record, 'other-handle'));
        self::assertNotNull($this->webauthn->assert($this->rp, $options, $this->parsed($none), $record, 'handle-bytes'));
        self::assertNotNull($this->webauthn->assert($this->rp, $options, $this->parsed($response), $record, null));
    }

    /**
     * A credential that the options do not allow is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialTheOptionsDoNotAllowIsRefused(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');
        $options       = $this->webauthn->requestOptions($this->rp, random_bytes(32), [['another-credential', []]], self::TIMEOUT);

        self::assertNull($this->webauthn->assert($this->rp, $options, $this->parsed($authenticator->get($options)), $record, 'handle-bytes'));
    }

    /**
     * The library leaves the counter to the package: an assertion whose count
     * does not advance still verifies, and reports its count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCounterIsLeftToThePackage(): void
    {
        $authenticator = new VirtualAuthenticator(self::ORIGIN);
        $record        = $this->registered($authenticator, 'handle-bytes');

        $record->counter = 50;

        self::assertSame(1, $this->asserted($authenticator, $record, null)?->counter);
    }

    /**
     * A relying party for the origins.
     *
     * @param  list<string>  $origins
     * @return \SineMacula\Laravel\Authentication\Passkeys\RelyingParty
     */
    private static function relyingParty(array $origins): RelyingParty
    {
        return RelyingParty::forGuard('web', new Repository([
            'app'            => ['name' => 'Example'],
            'auth'           => ['guards' => ['web' => ['driver' => 'jwt']]],
            'authentication' => ['passkeys' => ['relying_party' => ['id' => self::RP_ID, 'name' => null, 'origins' => $origins]]],
        ]));
    }

    /**
     * Fresh registration options for the user handle.
     *
     * @param  string  $handle
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function creation(string $handle = 'handle-bytes'): array
    {
        return $this->webauthn->creationOptions($this->rp, random_bytes(32), $handle, 'ada', 'Ada', [], self::TIMEOUT);
    }

    /**
     * Fresh usernameless request options.
     *
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function request(): array
    {
        return $this->webauthn->requestOptions($this->rp, random_bytes(32), [], self::TIMEOUT);
    }

    /**
     * Register a credential with the authenticator under the handle.
     *
     * @param  \Tests\Fixtures\Passkeys\VirtualAuthenticator  $authenticator
     * @param  string  $handle
     * @return \Webauthn\CredentialRecord
     *
     * @throws \Throwable
     */
    private function registered(VirtualAuthenticator $authenticator, string $handle): CredentialRecord
    {
        $options = $this->creation($handle);
        $record  = $this->webauthn->register($this->rp, $options, $this->parsed($authenticator->create($options)));

        self::assertNotNull($record);

        return $record;
    }

    /**
     * Assert with the authenticator against fresh options.
     *
     * @param  \Tests\Fixtures\Passkeys\VirtualAuthenticator  $authenticator
     * @param  \Webauthn\CredentialRecord  $record
     * @param  ?string  $handle
     * @return ?\Webauthn\CredentialRecord
     *
     * @throws \Throwable
     */
    private function asserted(VirtualAuthenticator $authenticator, CredentialRecord $record, ?string $handle): ?CredentialRecord
    {
        $options = $this->request();

        return $this->webauthn->assert($this->rp, $options, $this->parsed($authenticator->get($options)), $record, $handle);
    }

    /**
     * Parse a response that must be well formed.
     *
     * @param  array<array-key, mixed>  $response
     * @return \Webauthn\PublicKeyCredential
     */
    private function parsed(array $response): PublicKeyCredential
    {
        $parsed = $this->webauthn->credential($response);

        self::assertNotNull($parsed);

        return $parsed;
    }

    /**
     * The credential without the member.
     *
     * @param  array<string, mixed>  $credential
     * @param  string  $member
     * @return array<string, mixed>
     */
    private static function without(array $credential, string $member): array
    {
        unset($credential[$member]);

        return $credential;
    }

    /**
     * The credential with its response's members changed; a `null` removes one.
     *
     * @param  array<array-key, mixed>  $credential
     * @param  array<string, mixed>  $changes
     * @return array<array-key, mixed>
     */
    private static function response(array $credential, array $changes): array
    {
        $response = is_array($credential['response'] ?? null) ? $credential['response'] : [];

        foreach ($changes as $member => $value) {

            if ($value === null) {
                unset($response[$member]);

                continue;
            }

            $response[$member] = $value;
        }

        return ['response' => $response] + $credential;
    }
}
