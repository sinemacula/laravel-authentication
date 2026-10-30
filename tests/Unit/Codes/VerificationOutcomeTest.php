<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;

/**
 * Pins the values a code verification's outcome is answered with: the three the
 * verifier gives an accepted code, under the values the verifier's own outcome
 * has, then the three a refused code gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class VerificationOutcomeTest extends TestCase
{
    /**
     * The values are fixed.
     *
     * @return void
     */
    public function testTheValuesAreFixed(): void
    {
        self::assertSame(['verified', 'already_verified', 'mismatch', 'invalid', 'expired', 'exhausted'], array_column(VerificationOutcome::cases(), 'value'));
    }
}
