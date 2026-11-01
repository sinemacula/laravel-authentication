<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use Tests\TestCase;

/**
 * Tests of what a sign-in carries to its session's first proofs: the first
 * factor a method verified, an external provider's, and an unattested one; the
 * first factor and provenance a pending sign-in keeps and reads back; and the
 * refusal of anything a pending sign-in keeps that cannot be read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInProof::class)]
final class SignInProofTest extends TestCase
{
    /**
     * A verified first factor keeps the method, the factor's channel,
     * observations and values, and its time to the whole second, as the
     * session's first proof.
     *
     * @return void
     */
    public function testAVerifiedFirstFactorBecomesTheFirstProof(): void
    {
        $observed = new ObservedProperties(true, true, true, false, true);
        $factor   = new FirstFactor(\Mockery::mock(Identity::class), new Channel(ChannelKind::PASSKEY, 'passkey-1'), $observed, ['pop']);
        $proof    = SignInProof::verified('passkey', $factor, CarbonImmutable::parse('2026-04-06 12:00:00.4'));
        $first    = $proof->firstFactor();

        self::assertSame(['passkey', ['pop']], [$proof->method, $proof->methods]);
        self::assertSame('2026-04-06 12:00:00.000000', $proof->authenticatedAt->format('Y-m-d H:i:s.u'));
        self::assertNull($proof->provenance);
        self::assertNull($proof->additional);
        self::assertSame(
            [ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'passkey', null, null, ['pop']],
            [$first->kind, $first->purpose, $first->method, $first->factor, $first->evaluation, $first->methods],
        );
        self::assertSame([$factor->channel, $observed, $proof->authenticatedAt], [$first->channel, $first->observed, $first->authenticatedAt]);
    }

    /**
     * An external provider's first factor is the connection, the private
     * external-provider value and the provider's time, with the provenance and
     * the provider's deadline; a time after now, or none, is now.
     *
     * @return void
     */
    public function testAnExternalFirstFactorIsTheProviders(): void
    {
        $now        = CarbonImmutable::parse('2026-04-06 12:00:00.6');
        $provenance = new Provenance('connection-7', providerAuthenticatedAt: $now->subMinutes(5), sessionNotAfter: $now->addHour());
        $proof      = SignInProof::external('sso', $provenance, $now);

        self::assertSame([ChannelKind::EXTERNAL_PROVIDER, 'connection-7'], [$proof->channel->kind, $proof->channel->reference]);
        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], $proof->methods);
        self::assertSame($now->subMinutes(5)->startOfSecond()->getTimestamp(), $proof->authenticatedAt->getTimestamp());
        self::assertSame($provenance, $proof->provenance);
        self::assertEquals(new ObservedProperties, $proof->observed);

        $atTheSecond = SignInProof::external('sso', new Provenance('connection-7', providerAuthenticatedAt: $now->startOfSecond()), $now);
        $ahead       = SignInProof::external('sso', new Provenance('connection-7', providerAuthenticatedAt: $now->addSecond()), $now);
        $untimed     = SignInProof::external('sso', new Provenance('connection-7'), $now);

        self::assertSame('2026-04-06 12:00:00.000000', $atTheSecond->authenticatedAt->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-04-06 12:00:00.000000', $ahead->authenticatedAt->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-04-06 12:00:00.000000', $untimed->authenticatedAt->format('Y-m-d H:i:s.u'));
    }

    /**
     * A sign-in the caller verified and did not describe names no channel and
     * no value, and is timed now.
     *
     * @return void
     */
    public function testAnUnattestedFirstFactorNamesNothing(): void
    {
        $proof = SignInProof::unattested('sso', CarbonImmutable::parse('2026-04-06 12:00:00.9'));

        self::assertSame(['sso', ChannelKind::UNKNOWN, null, []], [$proof->method, $proof->channel->kind, $proof->channel->reference, $proof->methods]);
        self::assertSame('2026-04-06 12:00:00.000000', $proof->authenticatedAt->format('Y-m-d H:i:s.u'));
    }

    /**
     * A completion's further factor is carried beside the first factor and its
     * provenance, which it leaves as they were.
     *
     * @return void
     */
    public function testAFurtherFactorIsCarriedBesideTheFirst(): void
    {
        $provenance = new Provenance('connection-7');
        $proof      = SignInProof::external('sso', $provenance, CarbonImmutable::now());
        $additional = new NewProof(
            ProofKind::ADDITIONAL_FACTOR,
            Purpose::SIGN_IN,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-1',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
        );
        $completed = $proof->withAdditional($additional);

        self::assertSame($additional, $completed->additional);
        self::assertSame([$proof->method, $proof->channel, $proof->observed, $proof->methods, $proof->authenticatedAt, $provenance], [
            $completed->method,
            $completed->channel,
            $completed->observed,
            $completed->methods,
            $completed->authenticatedAt,
            $completed->provenance,
        ]);
        self::assertNull($proof->additional);
    }

    /**
     * The first factor and provenance a pending sign-in keeps read back as they
     * were, under the method the pending sign-in records.
     *
     * @return void
     */
    public function testAPendingSignInReadsBackWhatItKept(): void
    {
        $observed   = new ObservedProperties(true, false, false, true, true, KeyProtection::SOFTWARE);
        $factor     = new FirstFactor(\Mockery::mock(Identity::class), new Channel(ChannelKind::EMAIL, 'ada@example.test'), $observed, ['otp']);
        $at         = CarbonImmutable::parse('2026-04-06 12:00:00');
        $provenance = new Provenance('connection-7', 'tenant-3', $at->subMinute(), $at->addHours(8), 'v12');
        $kept       = self::kept(SignInProof::verified('email_code', $factor, $at), $provenance);

        self::assertSame(['email_code', ChannelKind::EMAIL, 'ada@example.test', ['otp']], [$kept->method, $kept->channel->kind, $kept->channel->reference, $kept->methods]);
        self::assertSame([true, false, false, true, true, KeyProtection::SOFTWARE], [
            $kept->observed->userPresence,
            $kept->observed->userVerification,
            $kept->observed->backupEligible,
            $kept->observed->backupState,
            $kept->observed->phishingResistant,
            $kept->observed->keyProtection,
        ]);
        self::assertSame($at->getTimestamp(), $kept->authenticatedAt->getTimestamp());
        self::assertSame(date_default_timezone_get(), $kept->authenticatedAt->getTimezone()->getName());
        self::assertNotNull($kept->provenance);
        self::assertSame(['connection-7', 'tenant-3', 'v12'], [$kept->provenance->connectionId, $kept->provenance->tenantId, $kept->provenance->policyVersion]);
        self::assertSame($at->subMinute()->getTimestamp(), $kept->provenance->providerAuthenticatedAt?->getTimestamp());
        self::assertSame($at->addHours(8)->getTimestamp(), $kept->provenance->sessionNotAfter?->getTimestamp());

        $bare = self::kept(SignInProof::unattested('sso', $at), new Provenance('connection-7'));

        self::assertNull($bare->provenance?->providerAuthenticatedAt);
        self::assertNull($bare->provenance?->sessionNotAfter);
        self::assertNull($bare->provenance?->tenantId);
        self::assertNull(self::kept(SignInProof::unattested('sso', $at), null)->provenance);
    }

    /**
     * Rows of `[first factor, provenance]` a pending sign-in may not keep.
     *
     * @return iterable<string, array{0: mixed, 1: mixed}>
     */
    public static function provideUnreadable(): iterable
    {
        $valid = [
            'channel_kind'      => 'password',
            'channel_reference' => null,
            'observed'          => ['user_presence' => null, 'key_protection' => null],
            'methods'           => ['pwd'],
            'authenticated_at'  => 1775476800,
        ];

        yield from [
            'not an array'                          => ['password', null],
            'no channel'                            => [[...$valid, 'channel_kind' => null], null],
            'an unknown channel'                    => [[...$valid, 'channel_kind' => 'carrier_pigeon'], null],
            'a numeric reference'                   => [[...$valid, 'channel_reference' => 7], null],
            'an empty reference'                    => [[...$valid, 'channel_reference' => ''], null],
            'no observations'                       => [[...$valid, 'observed' => 'none'], null],
            'a flag that is not one'                => [[...$valid, 'observed' => ['user_presence' => 'yes']], null],
            'an unknown protection'                 => [[...$valid, 'observed' => ['key_protection' => 'vault']], null],
            'methods that are not'                  => [[...$valid, 'methods' => 'pwd'], null],
            'the reserved mfa'                      => [[...$valid, 'methods' => ['mfa']], null],
            'no time'                               => [[...$valid, 'authenticated_at' => null], null],
            'a time that is not one'                => [[...$valid, 'authenticated_at' => '2026-04-06'], null],
            'a provenance that is not one'          => [$valid, 'connection-7'],
            'a provenance without a connection'     => [$valid, ['tenant_id' => 't']],
            'a provenance with an empty connection' => [$valid, ['connection_id' => '']],
            'a provenance time that is not one'     => [$valid, ['connection_id' => 'c', 'session_not_after' => 'soon']],
        ];
    }

    /**
     * Anything else is a `LogicException` that keeps what refused it as its
     * cause, never a first factor read as something it was not.
     *
     * @param  mixed  $firstFactor
     * @param  mixed  $provenance
     * @return void
     */
    #[DataProvider('provideUnreadable')]
    public function testAPendingSignInThatKeptSomethingElseFailsClosed(mixed $firstFactor, mixed $provenance): void
    {
        $pending = new PendingSignIn;

        $pending->setRawAttributes([
            'sign_in_method' => 'password',
            'first_factor'   => json_encode($firstFactor, JSON_THROW_ON_ERROR),
            'provenance'     => $provenance === null ? null : json_encode($provenance, JSON_THROW_ON_ERROR),
        ]);

        try {
            SignInProof::kept($pending);

            self::fail('Expected the pending sign-in to fail closed.');
        } catch (\LogicException $exception) {
            self::assertSame('A pending sign-in keeps a first factor or provenance the package cannot read.', $exception->getMessage());
            self::assertNotNull($exception->getPrevious());
        }
    }

    /**
     * The valid first factor the rows above alter reads back.
     *
     * @return void
     */
    public function testTheValidKeptFirstFactorReads(): void
    {
        $pending = new PendingSignIn;

        $pending->setRawAttributes([
            'sign_in_method' => 'password',
            'first_factor'   => json_encode([
                'channel_kind'      => 'password',
                'channel_reference' => null,
                'observed'          => ['user_presence' => null, 'key_protection' => null],
                'methods'           => ['pwd'],
                'authenticated_at'  => 1775476800,
            ], JSON_THROW_ON_ERROR),
            'provenance' => json_encode(['connection_id' => 'c'], JSON_THROW_ON_ERROR),
        ]);

        $kept = SignInProof::kept($pending);

        self::assertSame(
            [ChannelKind::PASSWORD, ['pwd'], 1775476800, 'c'],
            [$kept->channel->kind, $kept->methods, $kept->authenticatedAt->getTimestamp(), $kept->provenance?->connectionId],
        );
    }

    /**
     * The proof as a pending sign-in recording the given provenance would keep
     * and read it back.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @return \SineMacula\Laravel\Authentication\Proofs\SignInProof
     */
    private static function kept(SignInProof $proof, ?Provenance $provenance): SignInProof
    {
        $carried = $provenance === null ? $proof : SignInProof::external($proof->method, $provenance, $proof->authenticatedAt);
        $pending = new PendingSignIn;

        $pending->forceFill([
            'sign_in_method' => $proof->method,
            'first_factor'   => $proof->toArray(),
            'provenance'     => $provenance === null ? null : $carried->provenanceToArray(),
        ]);

        self::assertNull($provenance === null ? $proof->provenanceToArray() : null);

        return SignInProof::kept($pending);
    }
}
