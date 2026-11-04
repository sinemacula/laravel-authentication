<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\PendingActionRefused;

/**
 * Unit tests for the refusal a pending action throws to roll its transaction
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingActionRefused::class)]
final class PendingActionRefusedTest extends TestCase
{
    /**
     * It carries the refusal it is answered with, and names the reason, nothing
     * more, in its message.
     *
     * @return void
     */
    public function testCarriesTheRefusal(): void
    {
        $refused = new Refused(FailureReason::PENDING_INVALID);
        $thrown  = new PendingActionRefused($refused);

        self::assertSame($refused, $thrown->refused);
        self::assertSame('The pending action was refused: pending_invalid.', $thrown->getMessage());
    }
}
