<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for what a further factor's or an enrolment's code is bound to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorCodeBinding::class)]
final class FactorCodeBindingTest extends TestCase
{
    /** @var string The destination the codes go to. */
    private const string PHONE = '+447700900123';

    /**
     * Rows of `[proof purpose, grant, challenge purpose]`: sign-in and step-up
     * codes are `mfa`, an enrolment's `enrollment`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose, 1: ?string, 2: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose}>
     */
    public static function providePurposes(): iterable
    {
        yield from [
            'a sign-in'    => [Purpose::SIGN_IN, null, CodePurpose::MFA],
            'a step-up'    => [Purpose::STEP_UP, null, CodePurpose::MFA],
            'an enrolment' => [Purpose::ENROLLMENT, 'grant-1', CodePurpose::ENROLLMENT],
        ];
    }

    /**
     * The binding keeps what it was given and says which challenge it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  ?string  $grant
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $expected
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testThePurposeNamesTheChallenge(Purpose $purpose, ?string $grant, CodePurpose $expected): void
    {
        $proof   = self::proof($purpose);
        $channel = new Channel(ChannelKind::SMS, self::PHONE);
        $binding = new FactorCodeBinding($proof, 'factor-1', $channel, $grant);

        self::assertSame([$proof, 'factor-1', $channel, $grant], [$binding->binding, $binding->factor, $binding->channel, $binding->grant]);
        self::assertSame($expected, $binding->purpose());
    }

    /**
     * Rows of `[binding, message]`: every binding refused before any code is
     * sent or checked.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding, 1: string}>
     */
    public static function provideRefusedBindings(): iterable
    {
        $sms = new Channel(ChannelKind::SMS, self::PHONE);

        yield from [
            'a reauthentication' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::REAUTHENTICATE), 'factor-1', $sms),
                'A factor code is for a sign-in, a step-up or an enrolment: a reauthentication proves the first factor.',
            ],
            'an empty factor' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN), '', $sms),
                'A factor code\'s factor reference must be from 1 to 255 characters.',
            ],
            'a factor too long' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN), str_repeat('é', 256), $sms),
                'A factor code\'s factor reference must be from 1 to 255 characters.',
            ],
            'an authenticator app' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::AUTHENTICATOR_APP, 'app')),
                'A factor code goes by text message or email: its channel must be `sms` or `email` and name the destination.',
            ],
            'no destination' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::EMAIL)),
                'A factor code goes by text message or email: its channel must be `sms` or `email` and name the destination.',
            ],
            'no session' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN, null), 'factor-1', $sms),
                'A factor code is bound to a session: its binding must name the session\'s key.',
            ],
            'an empty session' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN, ''), 'factor-1', $sms),
                'A factor code is bound to a session: its binding must name the session\'s key.',
            ],
            'a grant on a sign-in' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::SIGN_IN), 'factor-1', $sms, 'grant-1'),
                'Only an enrolment\'s factor code is bound to an enrolment grant.',
            ],
            'a grant on a step-up' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::STEP_UP), 'factor-1', $sms, 'grant-1'),
                'Only an enrolment\'s factor code is bound to an enrolment grant.',
            ],
            'an enrolment without its grant' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::ENROLLMENT), 'factor-1', $sms),
                'A factor code\'s enrolment grant must be from 1 to 255 characters.',
            ],
            'an empty grant' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::ENROLLMENT), 'factor-1', $sms, ''),
                'A factor code\'s enrolment grant must be from 1 to 255 characters.',
            ],
            'a grant too long' => [
                static fn (): FactorCodeBinding => new FactorCodeBinding(self::proof(Purpose::ENROLLMENT), 'factor-1', $sms, str_repeat('g', 256)),
                'A factor code\'s enrolment grant must be from 1 to 255 characters.',
            ],
        ];
    }

    /**
     * A binding a factor code cannot be bound to is a misconfiguration.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $build
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedBindings')]
    public function testRefusesABindingAFactorCodeCannotHave(\Closure $build, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    /**
     * A factor reference and a grant of 255 characters, multibyte ones
     * included, and an integer session key, are accepted.
     *
     * @return void
     */
    public function testAcceptsTheLongestReferencesAndAnIntegerSession(): void
    {
        $binding = new FactorCodeBinding(self::proof(Purpose::ENROLLMENT, 42), str_repeat('é', 255), new Channel(ChannelKind::EMAIL, 'ada@example.test'), str_repeat('g', 255));

        self::assertSame([255, 255, 42], [mb_strlen($binding->factor), strlen((string) $binding->grant), $binding->binding->sessionId]);
    }

    /**
     * The grant is a sensitive parameter.
     *
     * @return void
     */
    public function testTheGrantIsSensitive(): void
    {
        self::assertNotSame([], (new \ReflectionParameter([FactorCodeBinding::class, '__construct'], 'grant'))->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A proof binding for the identity on the `mobile` application, for the
     * session given, with the purpose.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  mixed  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofBinding
     */
    private static function proof(Purpose $purpose, mixed $session = 'session-1'): ProofBinding
    {
        return new ProofBinding(new PlainIdentityFixture(7), 'mobile', $session, $purpose);
    }
}
