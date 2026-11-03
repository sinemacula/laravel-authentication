<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssertion;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * Unit tests for how verifying a passkey as a further factor ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorResult::class)]
final class PasskeyFactorResultTest extends TestCase
{
    /**
     * A verified factor carries what its assertion showed and no reason.
     *
     * @return void
     */
    public function testAVerifiedResultCarriesTheAssertion(): void
    {
        $now       = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $passkey   = new PasskeySummary('0192f6b2-0000-7000-8000-000000000001', 'Laptop', ['internal'], null, true, true, $now, $now);
        $assertion = new PasskeyFactorAssertion($passkey->id, 'Y3JlZGVudGlhbA', new ObservedProperties(true, false, true, true, true), $now, $passkey);
        $result    = PasskeyFactorResult::verified($assertion);

        self::assertTrue($result->isVerified());
        self::assertFalse($result->isFailed());
        self::assertSame($assertion, $result->assertion);
        self::assertNull($result->reason);
    }

    /**
     * A refused factor carries its reason and no assertion.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $result = PasskeyFactorResult::failed(FailureReason::PASSKEY_COUNTER_REGRESSED);

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isVerified());
        self::assertNull($result->assertion);
        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED, $result->reason);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(PasskeyFactorResult::class, '__construct'))->isPrivate());
    }
}
