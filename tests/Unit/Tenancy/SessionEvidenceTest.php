<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for the evidence a sign-in carries before its session is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionEvidence::class)]
final class SessionEvidenceTest extends TestCase
{
    /**
     * A sign-in no provider established holds its first factor, under the
     * proof's id, as its one proof, and no connection.
     *
     * @return void
     */
    public function testASignInsEvidenceIsItsFirstFactorAlone(): void
    {
        $at    = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $proof = UndescribedSignInProof::of('password', $at);

        $evidence = SessionEvidence::of($proof);

        self::assertSame($proof->id, $evidence->firstFactor->id);
        self::assertSame(ProofKind::FIRST_FACTOR, $evidence->firstFactor->kind);
        self::assertSame(Purpose::SIGN_IN, $evidence->firstFactor->purpose);
        self::assertSame('password', $evidence->firstFactor->method);
        self::assertSame($at->getTimestamp(), $evidence->firstFactor->authenticatedAt->getTimestamp());
        self::assertSame([$evidence->firstFactor], $evidence->proofs);
        self::assertNull($evidence->connectionId);
    }

    /**
     * A sign-in an external provider established carries the connection it came
     * through.
     *
     * @return void
     */
    public function testAnExternalSignInsEvidenceNamesItsConnection(): void
    {
        $evidence = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', 'tenant-1'), CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0)));

        self::assertSame('conn-a', $evidence->connectionId);
        self::assertSame('sso', $evidence->firstFactor->method);
        self::assertCount(1, $evidence->proofs);
        self::assertNull($evidence->externalEvidence);
    }

    /**
     * An external sign-in whose evidence was accepted carries it; a sign-in no
     * provider established carries none.
     *
     * @return void
     */
    public function testAnExternalSignInsEvidenceCarriesItsAcceptedEvidence(): void
    {
        $now      = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $accepted = new ExternalEvidence(['hwk'], 'phrh', $now);
        $evidence = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $accepted), $now, new Evaluation(true, true)));

        self::assertSame($accepted, $evidence->externalEvidence);
        self::assertSame($accepted, $evidence->firstFactor->evidence);
        self::assertNull(SessionEvidence::of(UndescribedSignInProof::of('password', $now))->externalEvidence);
    }
}
