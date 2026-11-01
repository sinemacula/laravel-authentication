<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use Tests\TestCase;

/**
 * Tests of what a sign-in carries to its session's first proofs: the first
 * factor a method verified, an external provider's, and an unattested one.
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
}
