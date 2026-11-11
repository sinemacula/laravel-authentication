<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;

/**
 * Unit tests for the factor package's answer for a factor code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorCodeAdmission::class)]
#[CoversClass(FactorCodeStanding::class)]
#[CoversClass(FactorCodeRefusal::class)]
final class FactorCodeAdmissionTest extends TestCase
{
    /**
     * An admitted code carries neither a lock nor a reason.
     *
     * @return void
     */
    public function testAnAdmittedCodeCarriesNothingElse(): void
    {
        $admission = FactorCodeAdmission::admitted();

        self::assertSame([FactorCodeStanding::ADMITTED, null, null], [$admission->standing, $admission->lockedUntil, $admission->refusal]);
        self::assertTrue($admission->isAdmitted());
    }

    /**
     * A locked code carries until when, or nothing when the factor package did
     * not say, and no reason.
     *
     * @return void
     */
    public function testALockedCodeCarriesItsEnd(): void
    {
        $until  = CarbonImmutable::createStrict(2026, 4, 6, 12, 15, 0);
        $locked = FactorCodeAdmission::locked($until);

        self::assertSame([FactorCodeStanding::LOCKED, $until, null], [$locked->standing, $locked->lockedUntil, $locked->refusal]);
        self::assertNull(FactorCodeAdmission::locked()->lockedUntil);
        self::assertFalse($locked->isAdmitted());
    }

    /**
     * A refused code carries why, and no lock.
     *
     * @return void
     */
    public function testARefusedCodeCarriesWhy(): void
    {
        $refused = FactorCodeAdmission::refused(FactorCodeRefusal::SENDING_CAPPED);

        self::assertSame([FactorCodeStanding::REFUSED, null, FactorCodeRefusal::SENDING_CAPPED], [$refused->standing, $refused->lockedUntil, $refused->refusal]);
        self::assertFalse($refused->isAdmitted());
    }

    /**
     * The standings and refusals are the factor package's values.
     *
     * @return void
     */
    public function testTheValuesAreTheFactorPackages(): void
    {
        self::assertSame(['admitted', 'locked', 'refused'], array_column(FactorCodeStanding::cases(), 'value'));
        self::assertSame(
            ['not_found', 'type_not_enabled', 'no_factor', 'identity_inactive', 'machine_identity', 'sending_capped', 'not_accepted'],
            array_column(FactorCodeRefusal::cases(), 'value'),
        );
    }
}
