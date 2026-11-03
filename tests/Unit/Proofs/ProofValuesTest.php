<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationMethods;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Unit tests for the proof value types: what each keeps, the shape each
 * constructor checks (lengths that fit the columns, `amr` values a column can
 * hold, `mfa` reserved), and the times kept to the whole second. None of them
 * decides acceptance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Channel::class)]
#[CoversClass(ObservedProperties::class)]
#[CoversClass(Evaluation::class)]
#[CoversClass(AuthenticationMethods::class)]
#[CoversClass(FirstFactor::class)]
#[CoversClass(ProofBinding::class)]
#[CoversClass(ProofResult::class)]
#[CoversClass(Provenance::class)]
#[CoversClass(NewProof::class)]
#[CoversClass(RecordedProof::class)]
final class ProofValuesTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A channel keeps its kind and reference, with no reference by default and
     * one of up to 255 characters, counted as characters, not bytes.
     *
     * @return void
     */
    public function testAChannelKeepsAReferenceThatFitsItsColumn(): void
    {
        self::assertNull((new Channel(ChannelKind::PASSWORD))->reference);
        self::assertSame(str_repeat('é', 255), (new Channel(ChannelKind::EMAIL, str_repeat('é', 255)))->reference);
        self::assertSame(ChannelKind::SMS, (new Channel(ChannelKind::SMS, '+447700900123'))->kind);
        self::assertSame(255, Channel::REFERENCE_MAX_LENGTH);
    }

    /**
     * Rows of references a channel refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedReferences(): iterable
    {
        yield from [
            'empty'    => [''],
            'too long' => [str_repeat('a', 256)],
        ];
    }

    /**
     * An empty reference, or one longer than its column, is refused.
     *
     * @param  string  $reference
     * @return void
     */
    #[DataProvider('provideRefusedReferences')]
    public function testAChannelRefusesAReferenceThatDoesNotFit(string $reference): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A channel reference must be from 1 to 255 characters, or null for none.');

        new Channel(ChannelKind::EMAIL, $reference);
    }

    /**
     * Nothing is observed by default: every property is `null`, never `true`.
     *
     * @return void
     */
    public function testNothingIsObservedByDefault(): void
    {
        $observed = new ObservedProperties;

        self::assertSame(
            [null, null, null, null, null, null],
            [$observed->userPresence, $observed->userVerification, $observed->backupEligible, $observed->backupState, $observed->phishingResistant, $observed->keyProtection],
        );

        $seen = new ObservedProperties(true, false, true, false, true, KeyProtection::HARDWARE);

        self::assertSame(
            [true, false, true, false, true, KeyProtection::HARDWARE],
            [$seen->userPresence, $seen->userVerification, $seen->backupEligible, $seen->backupState, $seen->phishingResistant, $seen->keyProtection],
        );
    }

    /**
     * An evaluation keeps what the adapter reported.
     *
     * @return void
     */
    public function testAnEvaluationKeepsWhatTheAdapterReported(): void
    {
        $evaluation = new Evaluation(true, false);

        self::assertSame([true, false], [$evaluation->accepted, $evaluation->multifactor]);
    }

    /**
     * A list of up to eight values, each 1 to 48 printable ASCII characters, is
     * kept as given.
     *
     * @return void
     */
    public function testAuthenticationMethodsKeepAValidList(): void
    {
        $values = ['pwd', 'otp', 'urn:sinemacula:amr:external_provider', str_repeat('x', 48), '~!#$%&\'()*+,-./', 'a', 'b', 'c'];

        self::assertSame($values, AuthenticationMethods::assertValid($values));
        self::assertSame([], AuthenticationMethods::assertValid([]));
        self::assertSame('mfa', AuthenticationMethods::MULTIFACTOR);
    }

    /**
     * Rows of `[values, message]`: lists a proof's `amr` values may not be.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideRefusedMethods(): iterable
    {
        $list  = 'A proof\'s `amr` values must be a list of at most 8.';
        $value = 'A proof\'s `amr` value must be 1 to 48 printable ASCII characters, no quote or backslash.';

        yield from [
            'a map'             => [['first' => 'pwd'], $list],
            'nine values'       => [array_fill(0, 9, 'otp'), $list],
            'an empty value'    => [[''], $value],
            'a long value'      => [[str_repeat('x', 49)], $value],
            'a number'          => [[7], $value],
            'a space'           => [['one time'], $value],
            'a quote'           => [['o"tp'], $value],
            'a backslash'       => [['o\tp'], $value],
            'non-ASCII'         => [['otpé'], $value],
            'a control byte'    => [["otp\n"], $value],
            'mfa and a newline' => [["mfa\n"], $value],
            '48 and a newline'  => [[str_repeat('x', 48) . "\n"], $value],
            'the reserved mfa'  => [['pwd', 'mfa'], '`mfa` is reserved: it is never a proof\'s own `amr` value, only an accepted evaluation\'s report.'],
        ];
    }

    /**
     * Anything else is refused, `mfa` above all.
     *
     * @param  array<array-key, mixed>  $values
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedMethods')]
    public function testAuthenticationMethodsRefuseAnythingElse(array $values, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        AuthenticationMethods::assertValid($values);
    }

    /**
     * A first factor keeps the identity, channel, observations and values,
     * observing nothing and standing for no value by default, and refuses
     * `mfa`.
     *
     * @return void
     */
    public function testAFirstFactorKeepsWhatTheMethodVerified(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $factor   = new FirstFactor($identity, new Channel(ChannelKind::PASSWORD));

        self::assertSame($identity, $factor->identity);
        self::assertEquals(new ObservedProperties, $factor->observed);
        self::assertSame([], $factor->methods);
        self::assertSame(['pop'], (new FirstFactor($identity, new Channel(ChannelKind::PASSKEY), new ObservedProperties(true), ['pop']))->methods);

        foreach (["mfa\n", "pwd\n"] as $trailing) {

            try {
                new FirstFactor($identity, new Channel(ChannelKind::PASSWORD), methods: [$trailing]);
                self::fail('Expected a value ending in a newline to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('printable ASCII', $exception->getMessage());
            }
        }

        $this->expectException(\InvalidArgumentException::class);

        new FirstFactor($identity, new Channel(ChannelKind::PASSWORD), methods: ['pwd', 'mfa']);
    }

    /**
     * A binding keeps what it binds the proof to, and must name an application.
     *
     * @return void
     */
    public function testABindingNamesItsApplication(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $binding  = new ProofBinding($identity, 'api', 'session-1', Purpose::STEP_UP);

        self::assertSame([$identity, 'api', 'session-1', Purpose::STEP_UP], [$binding->identity, $binding->application, $binding->sessionId, $binding->purpose]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A proof\'s binding must name the application it was made on.');

        new ProofBinding($identity, '', 'session-1', Purpose::STEP_UP);
    }

    /**
     * A proof result keeps everything the adapter handed over, its time cut to
     * the whole second in the time zone it was given in.
     *
     * @return void
     */
    public function testAProofResultKeepsWhatTheAdapterHandedOver(): void
    {
        $binding = new ProofBinding(\Mockery::mock(Identity::class), 'api', 'session-1', Purpose::STEP_UP);
        $result  = new ProofResult(
            ProofKind::RECOVERY_CODE,
            'recovery_code',
            new Channel(ChannelKind::UNKNOWN),
            null,
            new ObservedProperties,
            new Evaluation(true, false),
            ['otp'],
            CarbonImmutable::parse('2026-04-06 12:00:00.75', 'UTC'),
            $binding,
        );

        self::assertSame([ProofKind::RECOVERY_CODE, 'recovery_code', null, ['otp']], [$result->kind, $result->method, $result->factor, $result->methods]);
        self::assertSame('2026-04-06 12:00:00.000000', $result->authenticatedAt->format('Y-m-d H:i:s.u'));
        self::assertSame($binding, $result->binding);
        self::assertSame(255, ProofResult::NAME_MAX_LENGTH);
    }

    /**
     * Rows of `[method, factor]` a proof result refuses.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideRefusedNames(): iterable
    {
        yield from [
            'an empty method' => ['', null],
            'a long method'   => [str_repeat('m', 256), null],
            'an empty factor' => ['totp', ''],
            'a long factor'   => ['totp', str_repeat('f', 256)],
        ];
    }

    /**
     * An empty method or factor reference, or one longer than its column, is
     * refused; one of 255 characters fits, counted as characters, not bytes.
     *
     * @param  string  $method
     * @param  ?string  $factor
     * @return void
     */
    #[DataProvider('provideRefusedNames')]
    public function testAProofResultRefusesNamesThatDoNotFit(string $method, ?string $factor): void
    {
        self::assertSame(str_repeat('f', 255), self::stepUpProof(str_repeat('m', 255), str_repeat('f', 255))->factor);

        $wide = self::stepUpProof(str_repeat('é', 255), str_repeat('é', 255));

        self::assertSame([str_repeat('é', 255), str_repeat('é', 255)], [$wide->method, $wide->factor]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A proof\'s method, and its factor reference when it has one, must be from 1 to 255 characters.');

        self::stepUpProof($method, $factor);
    }

    /**
     * A proof result refuses `mfa` among its values, and `mfa` or any value
     * followed by a newline, which a trimming reader would take for it.
     *
     * @return void
     */
    public function testAProofResultRefusesTheReservedMfa(): void
    {
        foreach (["mfa\n", "otp\n"] as $trailing) {

            try {
                self::stepUpProof('totp', null, [$trailing]);
                self::fail('Expected a value ending in a newline to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('printable ASCII', $exception->getMessage());
            }
        }

        $this->expectException(\InvalidArgumentException::class);

        self::stepUpProof('totp', null, ['otp', 'mfa']);
    }

    /**
     * A provenance keeps what the caller checked, the link's id and the
     * provider context, its times cut to the whole second, and nothing but the
     * connection by default; each value fits up to its column's length in
     * characters, not bytes.
     *
     * @return void
     */
    public function testAProvenanceKeepsWhatTheCallerChecked(): void
    {
        $authenticated = CarbonImmutable::parse('2026-04-06 11:58:00.5');
        $provenance    = new Provenance('connection-7', 'tenant-3', $authenticated, CarbonImmutable::parse('2026-04-06 20:00:00.9'), 'v12', 'Link-1 ');

        self::assertSame(
            ['connection-7', 'tenant-3', 'v12', 'Link-1 '],
            [$provenance->connectionId, $provenance->tenantId, $provenance->policyVersion, $provenance->linkId],
        );
        self::assertSame('2026-04-06 11:58:00.000000', $provenance->providerAuthenticatedAt?->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-04-06 20:00:00.000000', $provenance->sessionNotAfter?->format('Y-m-d H:i:s.u'));

        $bare = new Provenance(str_repeat('c', 255), str_repeat('t', 255), policyVersion: str_repeat('v', 64), linkId: str_repeat('l', 255));

        self::assertNull($bare->providerAuthenticatedAt);
        self::assertNull($bare->sessionNotAfter);
        self::assertNull((new Provenance('connection-7'))->linkId);
        self::assertNull($bare->evidence);
        self::assertNull($bare->providerContext);
        self::assertSame([255, 64], [Provenance::ID_MAX_LENGTH, Provenance::VERSION_MAX_LENGTH]);

        $wide = new Provenance(str_repeat('é', 255), str_repeat('é', 255), policyVersion: str_repeat('é', 64), linkId: str_repeat('é', 255));

        self::assertSame(
            [str_repeat('é', 255), str_repeat('é', 255), str_repeat('é', 64), str_repeat('é', 255)],
            [$wide->connectionId, $wide->tenantId, $wide->policyVersion, $wide->linkId],
        );

        $evidence = new ExternalEvidence(['pwd', 'otp'], 'urn:acr:mfa', CarbonImmutable::parse('2026-04-06 11:58:00'));

        self::assertSame($evidence, (new Provenance('connection-7', evidence: $evidence))->evidence);

        $context = new ProviderContext(['protocol' => 'saml']);

        self::assertSame($context, (new Provenance('connection-7', providerContext: $context))->providerContext);
    }

    /**
     * Rows of `[arguments, field]` a provenance refuses.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideRefusedProvenances(): iterable
    {
        yield from [
            'an empty connection' => [['connectionId' => ''], 'connection id'],
            'a long connection'   => [['connectionId' => str_repeat('c', 256)], 'connection id'],
            'an empty tenant'     => [['connectionId' => 'c', 'tenantId' => ''], 'tenant id'],
            'a long tenant'       => [['connectionId' => 'c', 'tenantId' => str_repeat('t', 256)], 'tenant id'],
            'an empty policy'     => [['connectionId' => 'c', 'policyVersion' => ''], 'policy version'],
            'a long policy'       => [['connectionId' => 'c', 'policyVersion' => str_repeat('v', 65)], 'policy version'],
            'an empty link'       => [['connectionId' => 'c', 'linkId' => ''], 'link id'],
            'a long link'         => [['connectionId' => 'c', 'linkId' => str_repeat('l', 256)], 'link id'],
        ];
    }

    /**
     * An empty value, or one longer than its column, is refused, naming it.
     *
     * @param  array<string, mixed>  $arguments
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideRefusedProvenances')]
    public function testAProvenanceRefusesValuesThatDoNotFit(array $arguments, string $field): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('A provenance\'s %s, when given, must be from 1 to %d characters.', $field, $field === 'policy version' ? 64 : 255));

        new Provenance(...$arguments); // @phpstan-ignore argument.type
    }

    /**
     * A proof about to be recorded keeps what an adapter's proof carries, its
     * purpose taken from the binding.
     *
     * @return void
     */
    public function testANewProofTakesAnAdaptersProofAsItIs(): void
    {
        $result = self::stepUpProof('totp', 'factor-1', ['otp']);
        $proof  = NewProof::fromResult($result);

        self::assertSame(
            [ProofKind::ADDITIONAL_FACTOR, Purpose::STEP_UP, 'totp', 'factor-1', ['otp']],
            [$proof->kind, $proof->purpose, $proof->method, $proof->factor, $proof->methods],
        );
        self::assertSame(
            [$result->channel, $result->observed, $result->evaluation, $result->authenticatedAt],
            [$proof->channel, $proof->observed, $proof->evaluation, $proof->authenticatedAt],
        );
        self::assertNull($proof->evidence);
    }

    /**
     * A recorded proof keeps what was read back.
     *
     * @return void
     */
    public function testARecordedProofKeepsWhatWasRead(): void
    {
        $at    = CarbonImmutable::parse('2026-04-06 12:00:00');
        $proof = new RecordedProof(
            'id-1',
            ProofKind::FIRST_FACTOR,
            Purpose::SIGN_IN,
            'password',
            new Channel(ChannelKind::PASSWORD),
            null,
            new ObservedProperties,
            null,
            ['pwd'],
            $at,
        );

        self::assertSame(['id-1', ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', null, null, ['pwd'], $at], [
            $proof->id,
            $proof->kind,
            $proof->purpose,
            $proof->method,
            $proof->factor,
            $proof->evaluation,
            $proof->methods,
            $proof->authenticatedAt,
        ]);
        self::assertSame(ChannelKind::PASSWORD, $proof->channel->kind);
        self::assertNull($proof->observed->userPresence);
        self::assertNull($proof->evidence);
    }

    /**
     * A step-up proof with the method, factor and values given.
     *
     * @param  string  $method
     * @param  ?string  $factor
     * @param  list<string>  $methods
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     *
     * @throws \InvalidArgumentException
     */
    private static function stepUpProof(string $method, ?string $factor, array $methods = []): ProofResult
    {
        return new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            $method,
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            $methods,
            CarbonImmutable::now(),
            new ProofBinding(\Mockery::mock(Identity::class), 'api', 'session-1', Purpose::STEP_UP),
        );
    }
}
