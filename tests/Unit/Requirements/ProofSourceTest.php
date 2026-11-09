<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for where a requirement judgement reads the authentication it
 * judges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofSource::class)]
final class ProofSourceTest extends TestCase
{
    /**
     * By default it reads the session's stored proofs, plainly.
     *
     * @return void
     */
    public function testByDefaultItReadsTheStoredProofsPlainly(): void
    {
        $source = new ProofSource;

        self::assertSame([null, false], [$source->evidence, $source->current]);
    }

    /**
     * It keeps the sign-in's evidence and whether the stored proofs are read
     * current, as given.
     *
     * @return void
     */
    public function testItKeepsTheEvidenceAndTheReadAsGiven(): void
    {
        $evidence = SessionEvidence::of(UndescribedSignInProof::of('password', CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0)));

        self::assertSame($evidence, (new ProofSource($evidence))->evidence);
        self::assertTrue((new ProofSource(current: true))->current);
    }
}
