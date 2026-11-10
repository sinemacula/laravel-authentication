<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use Tests\Fixtures\Proofs\UndescribedSignInProof;
use Tests\TestCase;

/**
 * Tests of what a sign-in carries to its session's first proofs: the first
 * factor a method verified, an external provider's, and an undescribed one.
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
     * An external sign-in whose evidence was accepted carries the acceptance on
     * its first factor and the evidence with it as written, and reads back with
     * the evidence alone, the acceptance being no requirement check's; one
     * without carries neither.
     *
     * @return void
     */
    public function testAnExternalFirstFactorCarriesItsAcceptedEvidence(): void
    {
        $now        = CarbonImmutable::parse('2026-04-06 12:00:00');
        $evidence   = new ExternalEvidence(['hwk'], 'phrh', $now->subMinute());
        $evaluation = new Evaluation(true, true);
        $proof      = SignInProof::external('sso', new Provenance('connection-7', evidence: $evidence), $now, $evaluation);

        self::assertSame($evaluation, $proof->evaluation);
        self::assertSame([$evaluation, $evidence], [$proof->firstFactor()->evaluation, $proof->firstFactor()->evidence]);
        self::assertSame([null, $evidence], [$proof->recorded()->evaluation, $proof->recorded()->evidence]);

        $plain = SignInProof::external('sso', new Provenance('connection-7'), $now);

        self::assertSame([null, null, null], [$plain->evaluation, $plain->firstFactor()->evaluation, $plain->recorded()->evidence]);
    }

    /**
     * The acceptance and the evidence come together or not at all: an
     * evaluation with no evidence, or evidence with no evaluation, is a
     * programming error.
     *
     * @return void
     */
    public function testAnExternalFirstFactorRefusesHalfAnAcceptance(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $evidence = new ExternalEvidence(['hwk'], null, $now);

        foreach ([[new Provenance('connection-7'), new Evaluation(true, false)], [new Provenance('connection-7', evidence: $evidence), null]] as [$provenance, $evaluation]) {
            try {
                SignInProof::external('sso', $provenance, $now, $evaluation);
                self::fail('Half an acceptance was taken.');
            } catch (\LogicException $exception) {
                self::assertSame('An external sign-in carries the acceptance of the provider\'s evidence and that evidence together, or neither.', $exception->getMessage());
            }
        }
    }

    /**
     * A first factor the caller did not describe names no channel and no value,
     * and is timed to the whole second it was given.
     *
     * @return void
     */
    public function testAnUndescribedFirstFactorNamesNothing(): void
    {
        $proof = UndescribedSignInProof::of('sso', CarbonImmutable::parse('2026-04-06 12:00:00.9'));

        self::assertSame(['sso', ChannelKind::UNKNOWN, null, []], [$proof->method, $proof->channel->kind, $proof->channel->reference, $proof->methods]);
        self::assertSame('2026-04-06 12:00:00.000000', $proof->authenticatedAt->format('Y-m-d H:i:s.u'));
    }

    /**
     * Each sign-in proof chooses its first factor's id, distinct per proof, and
     * reads back as the proof the session records under it.
     *
     * @return void
     */
    public function testTheFirstFactorReadsBackUnderItsOwnId(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $proof    = UndescribedSignInProof::of('sso', $now);
        $recorded = $proof->recorded();

        self::assertNotSame($proof->id, UndescribedSignInProof::of('sso', $now)->id);
        self::assertSame($proof->id, $recorded->id);
        self::assertSame(
            [ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'sso', null, null, [], $proof->authenticatedAt],
            [$recorded->kind, $recorded->purpose, $recorded->method, $recorded->factor, $recorded->evaluation, $recorded->methods, $recorded->authenticatedAt],
        );
        self::assertSame([$proof->channel, $proof->observed], [$recorded->channel, $recorded->observed]);
    }
}
