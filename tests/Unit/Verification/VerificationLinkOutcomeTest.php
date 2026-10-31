<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;

/**
 * Pins the values a verification link's outcome is answered with: the three the
 * verifier gives an accepted link, under the values the verifier's own outcome
 * has, then the two a refused link gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class VerificationLinkOutcomeTest extends TestCase
{
    /**
     * The values are fixed.
     *
     * @return void
     */
    public function testTheValuesAreFixed(): void
    {
        self::assertSame(['verified', 'already_verified', 'mismatch', 'invalid', 'expired'], array_column(VerificationLinkOutcome::cases(), 'value'));
    }

    /**
     * The verifier's outcomes keep their values in the link's outcome.
     *
     * @return void
     */
    public function testTheVerifiersOutcomesKeepTheirValues(): void
    {
        foreach (IdentifierVerification::cases() as $verification) {
            self::assertSame($verification->name, VerificationLinkOutcome::from($verification->value)->name);
        }
    }
}
