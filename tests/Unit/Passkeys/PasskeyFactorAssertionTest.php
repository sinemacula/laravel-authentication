<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssertion;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * Unit tests for what a verified factor assertion showed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorAssertion::class)]
final class PasskeyFactorAssertionTest extends TestCase
{
    /**
     * It carries the passkey's ids and what the assertion showed.
     *
     * @return void
     */
    public function testCarriesWhatTheAssertionShowed(): void
    {
        $at        = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $summary   = new PasskeySummary('0192f6b2-0000-7000-8000-000000000001', 'Laptop', ['internal'], null, true, false, $at, $at);
        $observed  = new ObservedProperties(true, false, true, false, true);
        $assertion = new PasskeyFactorAssertion($summary->id, 'Y3JlZGVudGlhbA', $observed, $at, $summary);

        self::assertSame(['passkeyId', 'credentialId', 'observed', 'assertedAt', 'passkey'], array_keys(get_object_vars($assertion)));
        self::assertSame([$summary->id, 'Y3JlZGVudGlhbA'], [$assertion->passkeyId, $assertion->credentialId]);
        self::assertSame($observed, $assertion->observed);
        self::assertSame($at, $assertion->assertedAt);
        self::assertSame($summary, $assertion->passkey);
    }
}
