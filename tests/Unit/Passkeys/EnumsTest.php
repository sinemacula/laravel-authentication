<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;

/**
 * Pins the values the passkey enums are stored and reported with: a challenge
 * row records its purpose, and an application answers a registration failure by
 * its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EnumsTest extends TestCase
{
    /**
     * The values are fixed.
     *
     * @return void
     */
    public function testTheValuesAreFixed(): void
    {
        self::assertSame(['register', 'sign_in', 'factor'], array_column(ChallengePurpose::cases(), 'value'));
        self::assertSame(['challenge_invalid', 'response_invalid', 'already_registered'], array_column(PasskeyRegistrationFailure::cases(), 'value'));
    }
}
