<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\IssuanceRefused;

/**
 * Unit tests for the refusal a proof issuance throws to roll its transaction
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuanceRefused::class)]
final class IssuanceRefusedTest extends TestCase
{
    /**
     * It carries the refusal it is answered with, and names the reason, nothing
     * more, in its message.
     *
     * @return void
     */
    public function testCarriesTheRefusal(): void
    {
        $refused = new Refused(FailureReason::ADDITIONAL_FACTOR_REQUIRED);
        $thrown  = new IssuanceRefused($refused);

        self::assertSame($refused, $thrown->refused);
        self::assertSame('The proof issuance was refused: additional_factor_required.', $thrown->getMessage());
    }
}
